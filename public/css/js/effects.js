// Three.js 3D Effects
let scene, camera, renderer, cube, particles;

function init3D() {
    const canvas = document.getElementById('three-canvas');
    if (!canvas) return;
    
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    
    renderer = new THREE.WebGLRenderer({ 
        canvas: canvas,
        alpha: true 
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);
    
    // Create floating cubes
    const geometry = new THREE.BoxGeometry(1, 1, 1);
    const material = new THREE.MeshBasicMaterial({ 
        color: 0x667eea,
        wireframe: true,
        transparent: true,
        opacity: 0.3
    });
    
    cube = new THREE.Mesh(geometry, material);
    scene.add(cube);
    
    // Add particle system
    const particleGeometry = new THREE.BufferGeometry();
    const particleCount = 1000;
    const posArray = new Float32Array(particleCount * 3);
    
    for(let i = 0; i < particleCount * 3; i += 3) {
        posArray[i] = (Math.random() - 0.5) * 50;
        posArray[i+1] = (Math.random() - 0.5) * 50;
        posArray[i+2] = (Math.random() - 0.5) * 50;
    }
    
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
    
    const particleMaterial = new THREE.PointsMaterial({
        color: 0x764ba2,
        size: 0.1,
        transparent: true,
        opacity: 0.5
    });
    
    particles = new THREE.Points(particleGeometry, particleMaterial);
    scene.add(particles);
    
    camera.position.z = 5;
    
    animate();
}

function animate() {
    requestAnimationFrame(animate);
    
    if (cube) {
        cube.rotation.x += 0.005;
        cube.rotation.y += 0.005;
    }
    
    if (particles) {
        particles.rotation.y += 0.0005;
    }
    
    renderer.render(scene, camera);
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    init3D();
});

// Handle window resize
window.addEventListener('resize', () => {
    if (camera && renderer) {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    }
});

// Mouse interaction effect
document.addEventListener('mousemove', (event) => {
    if (cube) {
        const mouseX = (event.clientX / window.innerWidth - 0.5) * 2;
        const mouseY = (event.clientY / window.innerHeight - 0.5) * 2;
        
        cube.rotation.y += mouseX * 0.01;
        cube.rotation.x += mouseY * 0.01;
    }
});

// Particle configuration for particles.js
const particlesConfig = {
    particles: {
        number: {
            value: 80,
            density: {
                enable: true,
                value_area: 800
            }
        },
        color: {
            value: "#667eea"
        },
        shape: {
            type: "circle",
            stroke: {
                width: 0,
                color: "#000000"
            }
        },
        opacity: {
            value: 0.5,
            random: true,
            anim: {
                enable: true,
                speed: 1,
                opacity_min: 0.1,
                sync: false
            }
        },
        size: {
            value: 3,
            random: true,
            anim: {
                enable: true,
                speed: 4,
                size_min: 0.3,
                sync: false
            }
        },
        line_linked: {
            enable: true,
            distance: 150,
            color: "#764ba2",
            opacity: 0.4,
            width: 1
        },
        move: {
            enable: true,
            speed: 2,
            direction: "none",
            random: true,
            straight: false,
            out_mode: "out",
            bounce: false,
            attract: {
                enable: true,
                rotateX: 600,
                rotateY: 1200
            }
        }
    },
    interactivity: {
        detect_on: "canvas",
        events: {
            onhover: {
                enable: true,
                mode: "grab"
            },
            onclick: {
                enable: true,
                mode: "push"
            },
            resize: true
        },
        modes: {
            grab: {
                distance: 140,
                line_linked: {
                    opacity: 1
                }
            },
            push: {
                particles_nb: 4
            }
        }
    },
    retina_detect: true
};

// Save config for particles.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = particlesConfig;
}
