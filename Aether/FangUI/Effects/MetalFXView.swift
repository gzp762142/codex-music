import Metal
import MetalKit
import UIKit

/// Metal 上下文：对应 Music 样本里的 MetalContext / MetalBuffer
final class MetalContext {
    static let shared = MetalContext()
    let device: MTLDevice?
    let commandQueue: MTLCommandQueue?
    let library: MTLLibrary?

    private init() {
        device = MTLCreateSystemDefaultDevice()
        commandQueue = device?.makeCommandQueue()
        library = device?.makeDefaultLibrary()
    }
}

/// 点阵 + 光束雨 + 粒子爆裂，统一由 MTKView 驱动
/// 对应原 effects.cpp + Music 的 Metal 悬浮绘制层
final class MetalFXView: MTKView {
    private var pipelineState: MTLRenderPipelineState?
    private var vertexBuffer: MTLBuffer?

    private struct Beam {
        var x: Float, y: Float, len: Float, speed: Float, life: Float, maxLife: Float
    }
    private struct Splash {
        var x: Float, y: Float, life: Float, maxLife: Float
    }
    private struct Particle {
        var x: Float, y: Float, vx: Float, vy: Float
        var life: Float, maxLife: Float, size: Float
    }

    private var beams: [Beam] = []
    private var splashes: [Splash] = []
    private var particles: [Particle] = []
    private var lastTime = CACurrentMediaTime()

    var showDots = true
    var showBeams = true
    var accent = Palette.light.accent
    var dotColor = Palette.light.dotGrid
    var themeT: CGFloat = 0

    private let maxVertices = 8192
    private var vertexData: [Float] = []
    private let vertexFloatCount = 6 // x,y,r,g,b,a

    override init(frame frameRect: CGRect, device: MTLDevice?) {
        super.init(frame: frameRect, device: device ?? MetalContext.shared.device)
        commonInit()
    }

    required init(coder: NSCoder) {
        super.init(coder: coder)
        device = MetalContext.shared.device
        commonInit()
    }

    private func commonInit() {
        framebufferOnly = false
        colorPixelFormat = .bgra8Unorm
        clearColor = MTLClearColor(red: 0, green: 0, blue: 0, alpha: 0)
        isPaused = false
        enableSetNeedsDisplay = false
        preferredFramesPerSecond = 60
        backgroundColor = .clear
        isOpaque = false
        delegate = self
        seedBeams()
        buildPipeline()
    }

    private func seedBeams() {
        beams = (0..<9).map { i in
            Beam(
                x: Float.random(in: 0.05...0.95),
                y: Float.random(in: -0.3...0.1),
                len: Float.random(in: 0.08...0.22),
                speed: Float.random(in: 0.35...0.85),
                life: Float(i) / 9,
                maxLife: Float.random(in: 1.2...2.4)
            )
        }
    }

    private func buildPipeline() {
        guard let device = self.device, let library = MetalContext.shared.library else { return }
        let desc = MTLRenderPipelineDescriptor()
        desc.vertexFunction = library.makeFunction(name: "fx_vertex")
        desc.fragmentFunction = library.makeFunction(name: "fx_fragment")
        desc.colorAttachments[0].pixelFormat = colorPixelFormat
        desc.colorAttachments[0].isBlendingEnabled = true
        desc.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
        desc.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
        desc.colorAttachments[0].sourceAlphaBlendFactor = .one
        desc.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha
        pipelineState = try? device.makeRenderPipelineState(descriptor: desc)
        vertexBuffer = device.makeBuffer(
            length: maxVertices * vertexFloatCount * MemoryLayout<Float>.size,
            options: .storageModeShared
        )
    }

    func emitBurst(at point: CGPoint, count: Int = 60) {
        for _ in 0..<count {
            let ang = Float.random(in: 0...(2 * .pi))
            let spd = Float.random(in: 0.15...0.55)
            particles.append(Particle(
                x: Float(point.x), y: Float(point.y),
                vx: cos(ang) * spd, vy: sin(ang) * spd,
                life: 0, maxLife: Float.random(in: 0.5...1.1),
                size: Float.random(in: 2...5)
            ))
        }
        if particles.count > 400 {
            particles.removeFirst(particles.count - 400)
        }
    }

    private func pushQuad(_ x0: Float, _ y0: Float, _ x1: Float, _ y1: Float,
                          _ r: Float, _ g: Float, _ b: Float, _ a: Float) {
        guard vertexData.count + 6 * 6 * vertexFloatCount < maxVertices * vertexFloatCount else { return }
        let pts: [(Float, Float)] = [
            (x0, y0), (x1, y0), (x1, y1),
            (x0, y0), (x1, y1), (x0, y1)
        ]
        for p in pts {
            vertexData.append(contentsOf: [p.0, p.1, r, g, b, a])
        }
    }

    private func pushCircle(_ cx: Float, _ cy: Float, _ radius: Float,
                            _ r: Float, _ g: Float, _ b: Float, _ a: Float, segments: Int = 16) {
        for i in 0..<segments {
            let a0 = Float(i) / Float(segments) * 2 * .pi
            let a1 = Float(i + 1) / Float(segments) * 2 * .pi
            guard vertexData.count + 3 * 6 * vertexFloatCount < maxVertices * vertexFloatCount else { return }
            vertexData.append(contentsOf: [cx, cy, r, g, b, a])
            vertexData.append(contentsOf: [cx + cos(a0) * radius, cy + sin(a0) * radius, r, g, b, a])
            vertexData.append(contentsOf: [cx + cos(a1) * radius, cy + sin(a1) * radius, r, g, b, a])
        }
    }

    private func accentRGBA() -> (Float, Float, Float, Float) {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        accent.getRed(&r, green: &g, blue: &b, alpha: &a)
        return (Float(r), Float(g), Float(b), Float(a))
    }

    private func dotRGBA() -> (Float, Float, Float, Float) {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        dotColor.getRed(&r, green: &g, blue: &b, alpha: &a)
        return (Float(r), Float(g), Float(b), Float(a))
    }

    private func rebuildVertices(w: Float, h: Float, dt: Float) {
        vertexData.removeAll(keepingCapacity: true)
        let ar = w / max(h, 1)

        // 点阵
        if showDots {
            let (dr, dg, db, da) = dotRGBA()
            let spacing: Float = 16
            // 半径按宽度归一化；0.0014 在 iPad 横屏下约 2pt 直径，接近原 UI 纹理。
            let radius: Float = 0.0014
            var y: Float = spacing * 0.5
            while y < h {
                var x: Float = spacing * 0.5
                while x < w {
                    // shader 里 ndcY = 1 - y*2 已经做过一次原点翻转，
                    // 这里必须传「原点左上」的 0..1，不能再翻。
                    pushCircle(x / w, y / h, radius, dr, dg, db, da, segments: 8)
                    x += spacing
                }
                y += spacing
            }
        }

        // 光束雨
        if showBeams {
            let (ar_, ag, ab, aa) = accentRGBA()
            for i in 0..<beams.count {
                var b = beams[i]
                b.y += b.speed * dt
                b.life += dt
                if b.y - b.len > 1 || b.life > b.maxLife {
                    b = Beam(
                        x: Float.random(in: 0.08...0.92),
                        y: -Float.random(in: 0.05...0.3),
                        len: Float.random(in: 0.08...0.22),
                        speed: Float.random(in: 0.35...0.85),
                        life: 0,
                        maxLife: Float.random(in: 1.2...2.4)
                    )
                }
                beams[i] = b
                let alpha = aa * 0.35 * min(1, b.life / 0.2) * min(1, (b.maxLife - b.life) / 0.4)
                let x0 = b.x - 0.002
                let x1 = b.x + 0.002
                let yTop = 1 - b.y
                let yBot = 1 - (b.y - b.len)
                pushQuad(x0, yTop, x1, yBot, ar_, ag, ab, alpha)
            }
        }

        // 粒子
        if !particles.isEmpty {
            let (ar_, ag, ab, _) = accentRGBA()
            var alive: [Particle] = []
            for p in particles {
                var q = p
                q.life += dt
                q.x += q.vx * dt
                q.y += q.vy * dt
                q.vy += 0.4 * dt
                if q.life < q.maxLife {
                    let t = 1 - q.life / q.maxLife
                    let px = q.x, py = q.y
                    let s = q.size / max(w, 1)
                    pushQuad(px - s, py - s, px + s, py + s, ar_, ag, ab, t)
                    alive.append(q)
                }
            }
            particles = alive
        }
        _ = ar
        _ = splashes
    }
}

extension MetalFXView: MTKViewDelegate {
    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {}

    func draw(in view: MTKView) {
        let now = CACurrentMediaTime()
        var dt = Float(now - lastTime)
        lastTime = now
        if dt > 0.1 { dt = 0.1 }

        guard let drawable = currentDrawable,
              let rpd = currentRenderPassDescriptor,
              let queue = MetalContext.shared.commandQueue,
              let pipelineState,
              let vertexBuffer,
              let cmd = queue.makeCommandBuffer(),
              let enc = cmd.makeRenderCommandEncoder(descriptor: rpd) else { return }

        let w = Float(bounds.width), h = Float(bounds.height)
        rebuildVertices(w: max(w, 1), h: max(h, 1), dt: dt)

        if !vertexData.isEmpty {
            let count = min(vertexData.count, maxVertices * vertexFloatCount)
            let ptr = vertexBuffer.contents().bindMemory(to: Float.self, capacity: count)
            for i in 0..<count { ptr[i] = vertexData[i] }
            enc.setRenderPipelineState(pipelineState)
            enc.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
            // MTLViewport 的单位是像素：用 bounds（点）会让绘制区域缩到
            // drawable 的 1/displayScale（Retina 上只剩左下四分之一）。
            let ds = drawableSize
            var viewport = MTLViewport(
                originX: 0, originY: 0,
                width: Double(ds.width), height: Double(ds.height),
                znear: 0, zfar: 1
            )
            enc.setVertexBytes(&viewport, length: MemoryLayout<MTLViewport>.size, index: 1)
            enc.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: count / vertexFloatCount)
        }
        enc.endEncoding()
        cmd.present(drawable)
        cmd.commit()
    }
}
