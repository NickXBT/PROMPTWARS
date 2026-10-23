/**
 * Interactive 3D Mascot for Phishing Shield AI.
 * Built with Three.js: Glossy dark graphite head, curved black glass visor,
 * violet eye rings, pointer tracking pupils, floating arms, and idle kinematics.
 * Includes graceful WebGL detection and reduced-motion support.
 */

import * as THREE from 'three';

export interface MascotOptions {
  container: HTMLElement;
  fallbackElement?: HTMLElement;
}

export class ShieldMascot {
  private container: HTMLElement;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private renderer: THREE.WebGLRenderer;
  private robotGroup: THREE.Group;
  private headGroup: THREE.Group;
  private leftArmGroup: THREE.Group;
  private rightArmGroup: THREE.Group;
  private leftEyePupil: THREE.Mesh;
  private rightEyePupil: THREE.Mesh;
  private leftEyeRing: THREE.Mesh;
  private rightEyeRing: THREE.Mesh;
  private antennaLight: THREE.PointLight;

  private targetRotationX = 0;
  private targetRotationY = 0;
  private currentRotationX = 0;
  private currentRotationY = 0;
  private targetPupilX = 0;
  private targetPupilY = 0;
  private currentPupilX = 0;
  private currentPupilY = 0;

  private animationFrameId: number | null = null;
  private clock = new THREE.Clock();
  private isVisible = true;
  private prefersReducedMotion = false;

  constructor(options: MascotOptions) {
    this.container = options.container;

    // Check prefers-reduced-motion
    if (typeof window !== 'undefined' && window.matchMedia) {
      this.prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    // Initialize Three.js scene
    this.scene = new THREE.Scene();

    const width = this.container.clientWidth || 400;
    const height = this.container.clientHeight || 450;

    this.camera = new THREE.PerspectiveCamera(38, width / height, 0.1, 100);
    this.camera.position.set(0, 0.2, 5.2);

    this.renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance'
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.1;

    this.container.appendChild(this.renderer.domElement);

    // Build robot components
    this.robotGroup = new THREE.Group();
    this.headGroup = new THREE.Group();
    this.leftArmGroup = new THREE.Group();
    this.rightArmGroup = new THREE.Group();

    // Setup materials
    const graphiteMaterial = new THREE.MeshStandardMaterial({
      color: 0x14151f,
      metalness: 0.85,
      roughness: 0.22,
      envMapIntensity: 1.0
    });

    const visorMaterial = new THREE.MeshPhysicalMaterial({
      color: 0x050508,
      metalness: 0.2,
      roughness: 0.08,
      transmission: 0.35,
      thickness: 0.6,
      transparent: true,
      opacity: 0.95
    });

    const violetGlowMaterial = new THREE.MeshBasicMaterial({
      color: 0x8b5cf6
    });

    const eyeRingMaterial = new THREE.MeshStandardMaterial({
      color: 0x7c4dff,
      emissive: 0x6d28d9,
      emissiveIntensity: 0.8,
      roughness: 0.3
    });

    const eyePupilMaterial = new THREE.MeshStandardMaterial({
      color: 0xa78bfa,
      emissive: 0xc4b5fd,
      emissiveIntensity: 1.2,
      roughness: 0.1
    });

    // 1. Head Chassis (curved rounded head)
    const headGeometry = new THREE.SphereGeometry(1.0, 36, 36);
    headGeometry.scale(1.15, 0.98, 0.92);
    const headMesh = new THREE.Mesh(headGeometry, graphiteMaterial);
    headMesh.castShadow = true;
    this.headGroup.appendChild(headMesh);

    // 2. Visor (curved dark shield face)
    const visorGeo = new THREE.CylinderGeometry(0.85, 0.82, 0.65, 32, 1, false, -Math.PI / 2.3, Math.PI / 1.15);
    visorGeo.rotateY(Math.PI / 2);
    const visorMesh = new THREE.Mesh(visorGeo, visorMaterial);
    visorMesh.position.set(0, 0.05, 0.38);
    visorMesh.scale.set(1.02, 0.9, 0.85);
    this.headGroup.appendChild(visorMesh);

    // 3. Eyes (Dual Expressive Violet Rings & Pupils)
    const eyeSpacing = 0.38;
    const eyeY = 0.06;
    const eyeZ = 0.94;

    // Left Eye Ring
    const ringGeo = new THREE.TorusGeometry(0.13, 0.022, 16, 32);
    this.leftEyeRing = new THREE.Mesh(ringGeo, eyeRingMaterial);
    this.leftEyeRing.position.set(-eyeSpacing, eyeY, eyeZ);
    this.headGroup.appendChild(this.leftEyeRing);

    // Right Eye Ring
    this.rightEyeRing = new THREE.Mesh(ringGeo.clone(), eyeRingMaterial);
    this.rightEyeRing.position.set(eyeSpacing, eyeY, eyeZ);
    this.headGroup.appendChild(this.rightEyeRing);

    // Left Pupil
    const pupilGeo = new THREE.SphereGeometry(0.065, 20, 20);
    this.leftEyePupil = new THREE.Mesh(pupilGeo, eyePupilMaterial);
    this.leftEyePupil.position.set(-eyeSpacing, eyeY, eyeZ + 0.01);
    this.headGroup.appendChild(this.leftEyePupil);

    // Right Pupil
    this.rightEyePupil = new THREE.Mesh(pupilGeo.clone(), eyePupilMaterial);
    this.rightEyePupil.position.set(eyeSpacing, eyeY, eyeZ + 0.01);
    this.headGroup.appendChild(this.rightEyePupil);

    // 4. Antenna & Sensor Node
    const antennaStemGeo = new THREE.CylinderGeometry(0.025, 0.03, 0.3, 16);
    const antennaStem = new THREE.Mesh(antennaStemGeo, graphiteMaterial);
    antennaStem.position.set(0, 1.08, 0);
    this.headGroup.appendChild(antennaStem);

    const antennaBallGeo = new THREE.SphereGeometry(0.08, 20, 20);
    const antennaBall = new THREE.Mesh(antennaBallGeo, violetGlowMaterial);
    antennaBall.position.set(0, 1.25, 0);
    this.headGroup.appendChild(antennaBall);

    this.antennaLight = new THREE.PointLight(0xa78bfa, 0.8, 2.5);
    this.antennaLight.position.set(0, 1.25, 0);
    this.headGroup.appendChild(this.antennaLight);

    // 5. Floating Robotic Arms
    const armGeo = new THREE.CapsuleGeometry(0.12, 0.45, 12, 20);
    const armMat = new THREE.MeshStandardMaterial({
      color: 0x181926,
      metalness: 0.75,
      roughness: 0.28
    });

    // Left arm
    const leftArmMesh = new THREE.Mesh(armGeo, armMat);
    leftArmMesh.rotation.z = 0.25;
    leftArmMesh.rotation.x = 0.15;
    this.leftArmGroup.position.set(-1.45, -0.2, 0);
    this.leftArmGroup.appendChild(leftArmMesh);

    // Right arm
    const rightArmMesh = new THREE.Mesh(armGeo.clone(), armMat);
    rightArmMesh.rotation.z = -0.25;
    rightArmMesh.rotation.x = -0.15;
    this.rightArmGroup.position.set(1.45, -0.2, 0);
    this.rightArmGroup.appendChild(rightArmMesh);

    // 6. Floor disc / soft ambient shadow
    const shadowGeo = new THREE.CircleGeometry(1.4, 32);
    shadowGeo.rotateX(-Math.PI / 2);
    const shadowMat = new THREE.MeshBasicMaterial({
      color: 0x0f172a,
      transparent: true,
      opacity: 0.12
    });
    const shadowMesh = new THREE.Mesh(shadowGeo, shadowMat);
    shadowMesh.position.set(0, -1.5, 0);
    this.robotGroup.appendChild(shadowMesh);

    // Assemble groups
    this.robotGroup.appendChild(this.headGroup);
    this.robotGroup.appendChild(this.leftArmGroup);
    this.robotGroup.appendChild(this.rightArmGroup);
    this.scene.appendChild(this.robotGroup);

    // Studio Lighting for clean surface
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.85);
    this.scene.appendChild(ambientLight);

    const keyLight = new THREE.DirectionalLight(0xffffff, 1.3);
    keyLight.position.set(3, 4, 4);
    this.scene.appendChild(keyLight);

    const rimLightLeft = new THREE.DirectionalLight(0x93c5fd, 1.2); // Soft blue rim
    rimLightLeft.position.set(-4, 2, -2);
    this.scene.appendChild(rimLightLeft);

    const rimLightRight = new THREE.DirectionalLight(0x7c4dff, 0.9); // Signature violet rim
    rimLightRight.position.set(4, -1, -2);
    this.scene.appendChild(rimLightRight);

    // Event listeners
    this.attachEventListeners();
    this.startAnimationLoop();
  }

  private attachEventListeners() {
    // Pointer tracking
    window.addEventListener('mousemove', (e) => {
      const rect = this.container.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;

      const normX = (e.clientX - centerX) / (window.innerWidth / 2);
      const normY = (e.clientY - centerY) / (window.innerHeight / 2);

      // Clamp target rotation
      this.targetRotationY = Math.max(-0.45, Math.min(0.45, normX * 0.55));
      this.targetRotationX = Math.max(-0.35, Math.min(0.35, normY * 0.45));

      // Pupils track cursor within visor
      this.targetPupilX = Math.max(-0.045, Math.min(0.045, normX * 0.05));
      this.targetPupilY = Math.max(-0.035, Math.min(0.035, -normY * 0.04));
    });

    // Resize handling
    window.addEventListener('resize', () => {
      if (!this.container) return;
      const width = this.container.clientWidth || 400;
      const height = this.container.clientHeight || 450;
      this.camera.aspect = width / height;
      this.camera.updateProjectionMatrix();
      this.renderer.setSize(width, height);
    });

    // Pause rendering when scrolled out of view for performance
    if (typeof IntersectionObserver !== 'undefined') {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          this.isVisible = entry.isIntersecting;
        });
      }, { threshold: 0.05 });
      observer.observe(this.container);
    }
  }

  private startAnimationLoop() {
    const animate = () => {
      this.animationFrameId = requestAnimationFrame(animate);

      if (!this.isVisible) return;

      const elapsed = this.clock.getElapsedTime();

      // Smooth lerp head rotation
      const lerpFactor = 0.08;
      this.currentRotationX += (this.targetRotationX - this.currentRotationX) * lerpFactor;
      this.currentRotationY += (this.targetRotationY - this.currentRotationY) * lerpFactor;

      this.headGroup.rotation.x = this.currentRotationX;
      this.headGroup.rotation.y = this.currentRotationY;

      // Smooth lerp pupil tracking
      this.currentPupilX += (this.targetPupilX - this.currentPupilX) * 0.12;
      this.currentPupilY += (this.targetPupilY - this.currentPupilY) * 0.12;

      this.leftEyePupil.position.x = -0.38 + this.currentPupilX;
      this.leftEyePupil.position.y = 0.06 + this.currentPupilY;
      this.rightEyePupil.position.x = 0.38 + this.currentPupilX;
      this.rightEyePupil.position.y = 0.06 + this.currentPupilY;

      if (!this.prefersReducedMotion) {
        // Floating sinusoidal kinematics
        const floatY = Math.sin(elapsed * 1.8) * 0.08;
        const breathScale = 1.0 + Math.sin(elapsed * 1.2) * 0.015;

        this.robotGroup.position.y = floatY;
        this.robotGroup.scale.set(breathScale, breathScale, breathScale);

        // Gentle floating arms sway
        this.leftArmGroup.position.y = -0.2 + Math.cos(elapsed * 1.6) * 0.06;
        this.leftArmGroup.rotation.z = 0.25 + Math.sin(elapsed * 1.4) * 0.05;

        this.rightArmGroup.position.y = -0.2 + Math.sin(elapsed * 1.6) * 0.06;
        this.rightArmGroup.rotation.z = -0.25 - Math.cos(elapsed * 1.4) * 0.05;

        // Subtle antenna pulse
        this.antennaLight.intensity = 0.7 + Math.sin(elapsed * 2.5) * 0.3;
      }

      this.renderer.render(this.scene, this.camera);
    };

    animate();
  }

  public destroy() {
    if (this.animationFrameId !== null) {
      cancelAnimationFrame(this.animationFrameId);
    }
    if (this.renderer && this.renderer.domElement && this.renderer.domElement.parentNode) {
      this.renderer.domElement.parentNode.removeChild(this.renderer.domElement);
    }
    this.renderer.dispose();
  }
}
