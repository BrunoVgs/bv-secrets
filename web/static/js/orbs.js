/* <bv-orbs> — WebGL background: trailing orbs, three passes with feedback
   (ping-pong render targets).

   Pass A  : draws 8 orbs on an animated 3D orbit.
   Pass B  : accumulates A into a target read back frame to frame, hence the
             persistent trail. 0.85 is the fade rate.
   Pass img: sums A and B and derives alpha, to composite over the page.

   three.js comes from esm.sh: if the CDN is unreachable the element stays empty
   and the form works normally.

   Attributes:
     offset-x  horizontal shift, in half-screen-widths. NEGATIVE = left, positive =
               right (the shader does `suv.x -= iOffsetX`). Default 0.
               Ref: -0.36 places the center near 30% of the width in 16:9.
     tint      "acc" (BV accent, default) or "raw" (original, cold tint)
*/
customElements.define('bv-orbs', class extends HTMLElement {
  static observedAttributes = ['offset-x'];

  attributeChangedCallback(name, _old, value) {
    if (name === 'offset-x' && this._setOffset) this._setOffset(parseFloat(value));
  }

  connectedCallback() {
    if (this._init) return;
    this._init = true;
    // Three full-screen passes per frame: skip if the user asked for less motion.
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    this._start().catch(() => {});
  }

  disconnectedCallback() {
    if (this._raf) cancelAnimationFrame(this._raf);
    if (this._ro) this._ro.disconnect();
    if (this._dispose) this._dispose();
  }

  async _start() {
    const THREE = await import('https://esm.sh/three@0.184.0');

    const W = () => Math.max(this.clientWidth, 1);
    const H = () => Math.max(this.clientHeight, 1);

    const renderer = new THREE.WebGLRenderer({
      alpha: true, antialias: false, powerPreference: 'high-performance',
    });
    // Cost is in pixels: three full-res passes quickly saturate a mobile GPU,
    // hence a lower cap on small screens.
    const cap = Math.min(window.innerWidth, window.innerHeight) < 700 ? 1.5 : 2;
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, cap));
    renderer.setSize(W(), H());
    this.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);

    const rtOpts = {
      minFilter: THREE.LinearFilter,
      magFilter: THREE.LinearFilter,
      format: THREE.RGBAFormat,
      type: THREE.HalfFloatType,
    };
    const rtA = new THREE.WebGLRenderTarget(W(), H(), rtOpts);
    const rtB1 = new THREE.WebGLRenderTarget(W(), H(), rtOpts);
    const rtB2 = new THREE.WebGLRenderTarget(W(), H(), rtOpts);
    let rtCur = rtB1, rtNext = rtB2;

    const VERT = `
      varying vec2 vUv;
      void main(){ vUv = uv; gl_Position = vec4(position, 1.0); }
    `;
    const PREFIX = `
      uniform vec3 iResolution;
      uniform float iTime;
      uniform sampler2D iChannel0;
      uniform sampler2D iChannel1;
      varying vec2 vUv;
    `;
    const SUFFIX = `
      void main(){
        vec4 fragColor = vec4(0.0);
        mainImage(fragColor, vUv * iResolution.xy);
        gl_FragColor = fragColor;
      }
    `;

    /* Per-channel exponents: the original (2.5,1.8,1.0) kills red and leaves a
       cold cast. Reversed, red survives longest and the trail takes the brand
       accent. */
    const tint = this.getAttribute('tint') === 'raw'
      ? 'vec3(2.5,1.8,1.0)'
      : 'vec3(1.0,2.9,3.4)';

    const res = () => new THREE.Vector3(W(), H(), 1);

    const matA = new THREE.ShaderMaterial({
      uniforms: { iResolution: { value: res() }, iTime: { value: 0 }, iOffsetX: { value: 0 } },
      vertexShader: VERT,
      fragmentShader: PREFIX + `
        uniform float iOffsetX;
        #define clamps(x) clamp(x,0.,1.)

        vec3 rX(vec3 p, float a){ vec3 q=p; float c=cos(a),s=sin(a);
          p.y=c*q.y-s*q.z; p.z=s*q.y+c*q.z; return p; }
        vec3 rY(vec3 p, float a){ vec3 q=p; float c=cos(a),s=sin(a);
          p.x=c*q.x+s*q.z; p.z=-s*q.x+c*q.z; return p; }
        vec3 rZ(vec3 p, float a){ vec3 q=p; float c=cos(a),s=sin(a);
          p.x=c*q.x-s*q.y; p.y=s*q.x+c*q.y; return p; }

        vec2 dirDist(float dir, float dist){ return vec2(cos(dir)*dist, sin(dir)*dist); }

        vec3 animation(vec2 uv, float time){
          float circles = 0.;
          for(float k=0.; k<8.; k++){
            vec3 pos = vec3(dirDist(time*k*0.1, 0.2), 0.);
            pos = rY(pos, time*1.1);
            pos = rZ(pos, time*2.15);
            pos = rX(pos, time*0.52);
            circles = max(circles, clamps(1.-(length(uv-pos.xy)*40.)));
          }
          return vec3(clamp(circles, 0., 1.));
        }

        void mainImage(out vec4 fragColor, in vec2 fragCoord){
          vec2 uv = fragCoord.xy/iResolution.xy;
          vec2 suv = uv - .5;
          suv.x /= iResolution.y/iResolution.x;
          suv.x -= iOffsetX;
          vec3 drawing = pow(animation(suv, iTime), ${tint});
          fragColor = vec4(drawing, 1.);
        }
      ` + SUFFIX,
      depthWrite: false, depthTest: false,
    });

    const matB = new THREE.ShaderMaterial({
      uniforms: {
        iResolution: { value: res() }, iTime: { value: 0 },
        iChannel0: { value: null }, iChannel1: { value: rtA.texture },
      },
      vertexShader: VERT,
      fragmentShader: PREFIX + `
        #define clamps(x) clamp(x,0.,1.)
        vec2 circle(float a){ return vec2(cos(a), sin(a)); }
        void mainImage(out vec4 fragColor, in vec2 fragCoord){
          vec2 uv = fragCoord.xy/iResolution.xy;
          vec4 d = vec4(0);
          #define L 8.
          for(float i=0.; i<L; i++){
            vec2 p = circle((i/L)*6.28318530718);
            p.x /= iResolution.x/iResolution.y;
            d = max(d, texture2D(iChannel1, uv + (p*0.00015)));
          }
          fragColor = (texture2D(iChannel0, uv)*0.85) + (clamps(d)*0.5);
        }
      ` + SUFFIX,
      depthWrite: false, depthTest: false,
    });

    const matImg = new THREE.ShaderMaterial({
      uniforms: {
        iResolution: { value: res() }, iTime: { value: 0 },
        iChannel0: { value: null }, iChannel1: { value: rtA.texture },
      },
      vertexShader: VERT,
      fragmentShader: PREFIX + `
        #define clamps(x) clamp(x,0.,1.)
        void mainImage(out vec4 fragColor, in vec2 fragCoord){
          vec2 uv = fragCoord.xy/iResolution.xy;
          vec4 base = texture2D(iChannel0, uv) + texture2D(iChannel1, uv);
          fragColor = vec4(base.xyz, clamps(length(base.xyz)*2.0));
        }
      ` + SUFFIX,
      transparent: true, blending: THREE.AdditiveBlending,
      depthWrite: false, depthTest: false,
    });

    const geometry = new THREE.PlaneGeometry(2, 2);
    const mesh = new THREE.Mesh(geometry, matA);
    scene.add(mesh);

    const parsed = parseFloat(this.getAttribute('offset-x'));
    matA.uniforms.iOffsetX.value = Number.isFinite(parsed) ? parsed : 0;
    this._setOffset = (v) => {
      if (Number.isFinite(v)) matA.uniforms.iOffsetX.value = v;
    };

    const resize = () => {
      const w = W(), h = H();
      renderer.setSize(w, h);
      [rtA, rtB1, rtB2].forEach((rt) => rt.setSize(w, h));
      [matA, matB, matImg].forEach((m) => m.uniforms.iResolution.value.set(w, h, 1));
    };
    this._ro = new ResizeObserver(resize);
    this._ro.observe(this);

    const clock = new THREE.Clock();
    const tick = () => {
      this._raf = requestAnimationFrame(tick);
      const t = clock.getElapsedTime();

      matA.uniforms.iTime.value = t;
      mesh.material = matA;
      renderer.setRenderTarget(rtA);
      renderer.render(scene, camera);

      matB.uniforms.iTime.value = t;
      matB.uniforms.iChannel0.value = rtCur.texture;
      mesh.material = matB;
      renderer.setRenderTarget(rtNext);
      renderer.render(scene, camera);

      const swap = rtCur; rtCur = rtNext; rtNext = swap;

      matImg.uniforms.iTime.value = t;
      matImg.uniforms.iChannel0.value = rtCur.texture;
      mesh.material = matImg;
      renderer.setRenderTarget(null);
      renderer.clear();
      renderer.render(scene, camera);
    };

    this._dispose = () => {
      geometry.dispose();
      [matA, matB, matImg].forEach((m) => m.dispose());
      [rtA, rtB1, rtB2].forEach((rt) => rt.dispose());
      renderer.dispose();
    };

    tick();
  }
});
