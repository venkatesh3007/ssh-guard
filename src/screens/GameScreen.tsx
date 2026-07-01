import { useEffect, useRef, useState, useCallback } from 'react';
import type { GameConfig, ShotResult } from '../types/game';

// ─── Sound Synthesis ─────────────────────────────────────────────────────────
const playSound = (type: 'goal' | 'miss' | 'save') => {
  try {
    const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);
    
    if (type === 'goal') {
      // Cheer-like sound - rising pitch
      oscillator.type = 'sine';
      oscillator.frequency.setValueAtTime(440, audioCtx.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(880, audioCtx.currentTime + 0.3);
      gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.5);
      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.5);
      
      // Second tone for harmony
      const osc2 = audioCtx.createOscillator();
      const gain2 = audioCtx.createGain();
      osc2.connect(gain2);
      gain2.connect(audioCtx.destination);
      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(554, audioCtx.currentTime);
      osc2.frequency.exponentialRampToValueAtTime(1108, audioCtx.currentTime + 0.3);
      gain2.gain.setValueAtTime(0.2, audioCtx.currentTime);
      gain2.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.5);
      osc2.start(audioCtx.currentTime);
      osc2.stop(audioCtx.currentTime + 0.5);
    } else if (type === 'save') {
      // Thud sound - low pitch drop
      oscillator.type = 'triangle';
      oscillator.frequency.setValueAtTime(200, audioCtx.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(50, audioCtx.currentTime + 0.3);
      gainNode.gain.setValueAtTime(0.4, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.3);
    } else if (type === 'miss') {
      // Dull thud - low and quick
      oscillator.type = 'sawtooth';
      oscillator.frequency.setValueAtTime(150, audioCtx.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(30, audioCtx.currentTime + 0.2);
      gainNode.gain.setValueAtTime(0.2, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.2);
      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.2);
    }
  } catch {
    // Audio not supported
  }
};

interface GameScreenProps {
  gameConfig: GameConfig;
  timeRemaining: number;
  isPlaying: boolean;
  score: number;
  shotsTaken: number;
  shotsMade: number;
  currentStreak: number;
  onShot: (result: ShotResult) => void;
  onGameOver: (finalScore: number) => void;
  setTimeRemaining: (time: number) => void;
  setIsPlaying: (playing: boolean) => void;
}

// ─── Constants ───────────────────────────────────────────────────────────────
const GRAVITY = 0.18;
const BALL_RADIUS = 13;
const GOAL_TOP = 110;
const GOAL_HEIGHT = 130;

interface Ball {
  x: number; y: number; vx: number; vy: number;
  radius: number; rotation: number;
  active: boolean; scored: boolean; saved: boolean; scale: number;
  targetX: number; targetY: number;
}

interface Goalkeeper {
  x: number; y: number;
  width: number; height: number;
  vx: number; state: 'idle' | 'anticipating' | 'diving' | 'celebrating' | 'sad';
  baseX: number;
  movePhase: number;
  reactionDelay: number;
  diveSpeed: number;
  diveTarget: number;
}

interface Particle { x: number; y: number; vx: number; vy: number; life: number; color: string; size: number; }

export default function GameScreen({
  gameConfig: _gameConfig,
  timeRemaining, isPlaying, score, shotsTaken, shotsMade,
  currentStreak: _currentStreak,
  onShot, onGameOver, setTimeRemaining, setIsPlaying,
}: GameScreenProps) {
  void _gameConfig; void _currentStreak;

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [gameState, setGameState] = useState<'aiming' | 'shooting' | 'result'>('aiming');
  const [message, setMessage] = useState('');
  const [showConfetti, setShowConfetti] = useState(false);

  const ballRef = useRef<Ball>({
    x: 0, y: 0, vx: 0, vy: 0, radius: BALL_RADIUS, rotation: 0,
    active: false, scored: false, saved: false, scale: 1,
    targetX: 0, targetY: 0,
  });
  const keeperRef = useRef<Goalkeeper>({
    x: 0, y: 0, width: 55, height: 75, vx: 0, state: 'idle',
    baseX: 0, movePhase: 0, reactionDelay: 8, diveSpeed: 1, diveTarget: 0,
  });
  const particlesRef = useRef<Particle[]>([]);
  const animRef = useRef<number>(0);
  const mouseRef = useRef({ x: 0, y: 0 });
  const goalsRef = useRef(0);

  // ─── Resize ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const resize = () => {
      const c = containerRef.current;
      if (!c) return;
      canvas.width = c.clientWidth;
      canvas.height = c.clientHeight;
      resetPositions();
    };
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, []);

  // ─── Timer ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!isPlaying || timeRemaining <= 0) return;
    const t = setInterval(() => setTimeRemaining(timeRemaining - 1), 1000);
    return () => clearInterval(t);
  }, [isPlaying, timeRemaining, setTimeRemaining]);

  useEffect(() => {
    if (timeRemaining <= 0 && isPlaying) {
      setIsPlaying(false);
      onGameOver(score);
    }
  }, [timeRemaining, isPlaying, score, onGameOver, setIsPlaying]);

  const createParticles = useCallback((x: number, y: number, color: string, count: number) => {
    for (let i = 0; i < count; i++) particlesRef.current.push({
      x, y, vx: (Math.random() - 0.5) * 12, vy: (Math.random() - 0.5) * 12 - 4,
      life: 1, color, size: Math.random() * 5 + 2,
    });
  }, []);

  const resetPositions = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const w = canvas.width, h = canvas.height;
    ballRef.current = {
      x: w / 2, y: h - 100, vx: 0, vy: 0, radius: BALL_RADIUS,
      rotation: 0, active: false, scored: false, saved: false, scale: 1,
      targetX: w / 2, targetY: GOAL_TOP + GOAL_HEIGHT / 2,
    };
    keeperRef.current = {
      x: w / 2, y: GOAL_TOP + GOAL_HEIGHT - 10, width: 55, height: 75,
      vx: 0, state: 'idle', baseX: w / 2, movePhase: Math.random() * Math.PI * 2,
      reactionDelay: Math.max(4, 10 - goalsRef.current * 0.5), diveSpeed: Math.min(2, 1 + goalsRef.current * 0.1), diveTarget: w / 2,
    };
    setGameState('aiming');
    setMessage('');
    setShowConfetti(false);
  }, []);

  // ─── Input ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const getPos = (e: MouseEvent | TouchEvent) => {
      const rect = canvas.getBoundingClientRect();
      const cx = 'touches' in e ? (e.touches[0]?.clientX ?? e.changedTouches[0]?.clientX) : e.clientX;
      const cy = 'touches' in e ? (e.touches[0]?.clientY ?? e.changedTouches[0]?.clientY) : e.clientY;
      return { x: (cx || 0) - rect.left, y: (cy || 0) - rect.top };
    };

    const onMove = (e: MouseEvent | TouchEvent) => {
      const pos = getPos(e);
      mouseRef.current = pos;
      if (gameState === 'aiming') {
        ballRef.current.targetX = pos.x;
        ballRef.current.targetY = pos.y;
      }
    };

    const onClick = (e: MouseEvent | TouchEvent) => {
      if (gameState !== 'aiming') return;
      e.preventDefault();
      const pos = getPos(e);
      const ball = ballRef.current;
      const keeper = keeperRef.current;
      const canvas = canvasRef.current;
      if (!canvas) return;

      const w = canvas.width;
      const goalW = w * 0.72;
      const goalLeft = (w - goalW) / 2;
      const goalRight = (w + goalW) / 2;
      const fieldTop = GOAL_TOP;

      // Set target
      ball.targetX = pos.x;
      ball.targetY = pos.y;

      // Calculate velocity to reach target
      const dx = pos.x - ball.x;
      const dy = pos.y - ball.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const speed = Math.min(dist * 0.12, 16);
      const angle = Math.atan2(dy, dx);

      ball.vx = Math.cos(angle) * speed;
      ball.vy = Math.sin(angle) * speed;
      ball.active = true;

      // Keeper anticipates — starts moving toward target with delay
      keeper.state = 'anticipating';
      keeper.diveSpeed = Math.min(2.5, 1.2 + goalsRef.current * 0.15);

      // Keeper reaction: actively blocks with 70:30 win-to-block ratio
      setTimeout(() => {
        if (keeper.state === 'anticipating') {
          keeper.state = 'diving';
          
          // Smart keeper: tracks ball trajectory
          const timeToGoal = (fieldTop - ball.y) / Math.abs(ball.vy);
          const predictedLandingX = ball.x + ball.vx * timeToGoal;
          
          // Keeper skill increases with goals scored (gets harder)
          const skillLevel = Math.min(0.95, 0.65 + goalsRef.current * 0.03);
          const reactionError = (1 - skillLevel) * 120;
          
          // 70% block chance: keeper moves toward predicted landing
          let targetX = predictedLandingX;
          if (Math.random() > skillLevel) {
            targetX += (Math.random() - 0.5) * reactionError * 2;
          }
          
          // Clamp to goal area
          targetX = Math.max(goalLeft + 20, Math.min(goalRight - 20, targetX));
          
          keeper.diveTarget = targetX;
          keeper.vx = (targetX - keeper.x) / Math.max(8, 20 - goalsRef.current * 0.8);
        }
      }, 100 + Math.random() * 150);

      setGameState('shooting');
    };

    canvas.addEventListener('mousemove', onMove);
    canvas.addEventListener('touchmove', onMove, { passive: false });
    canvas.addEventListener('mousedown', onClick);
    canvas.addEventListener('touchstart', onClick, { passive: false });

    return () => {
      canvas.removeEventListener('mousemove', onMove);
      canvas.removeEventListener('touchmove', onMove);
      canvas.removeEventListener('mousedown', onClick);
      canvas.removeEventListener('touchstart', onClick);
    };
  }, [gameState]);

  // ─── Game Loop ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const drawField = (w: number, h: number) => {
      // Sky
      const sky = ctx.createLinearGradient(0, 0, 0, h * 0.4);
      sky.addColorStop(0, '#0a1f35'); sky.addColorStop(1, '#1d4a6e');
      ctx.fillStyle = sky; ctx.fillRect(0, 0, w, h * 0.4);

      // Stands with crowd
      ctx.fillStyle = '#060d1a'; ctx.fillRect(0, 30, w, 60);
      for (let i = 0; i < w; i += 5) {
        for (let j = 35; j < 80; j += 6) {
          ctx.fillStyle = `hsl(${200 + Math.random() * 50}, 55%, ${25 + Math.random() * 30}%)`;
          ctx.fillRect(i, j, 3, 4);
        }
      }

      // Field
      const fieldTop = GOAL_TOP;
      const goalW = w * 0.72;
      const grass = ctx.createLinearGradient(0, fieldTop, 0, h);
      grass.addColorStop(0, '#2a5c2e'); grass.addColorStop(1, '#3d8b42');
      ctx.fillStyle = grass;
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop);
      ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.lineTo(w, h);
      ctx.lineTo(0, h);
      ctx.closePath(); ctx.fill();

      // Stripes
      ctx.save();
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop); ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath(); ctx.clip();
      for (let i = -w; i < w * 2; i += 35) {
        ctx.fillStyle = 'rgba(255,255,255,0.03)';
        ctx.fillRect(i, fieldTop, 17, h - fieldTop);
      }
      ctx.restore();

      // Goal line
      ctx.strokeStyle = 'rgba(255,255,255,0.9)';
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop); ctx.lineTo((w + goalW) / 2, fieldTop); ctx.stroke();

      // Penalty box
      const boxW = goalW * 0.5;
      ctx.strokeStyle = 'rgba(255,255,255,0.5)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo((w - boxW) / 2, fieldTop + 60);
      ctx.lineTo((w - boxW) / 2, fieldTop);
      ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.lineTo((w + boxW) / 2, fieldTop + 60);
      ctx.stroke();

      // Penalty spot
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(w / 2, fieldTop + 60 + 30, 3, 0, Math.PI * 2); ctx.fill();

      // Goal posts
      const postH = 80;
      ctx.strokeStyle = '#fff'; ctx.lineWidth = 5;
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop); ctx.lineTo((w - goalW) / 2, fieldTop - postH);
      ctx.lineTo((w + goalW) / 2, fieldTop - postH); ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.stroke();

      // Net
      ctx.strokeStyle = 'rgba(255,255,255,0.2)'; ctx.lineWidth = 1;
      for (let x = (w - goalW) / 2; x <= (w + goalW) / 2; x += 10) {
        ctx.beginPath(); ctx.moveTo(x, fieldTop - postH); ctx.lineTo(x, fieldTop); ctx.stroke();
      }
      for (let y = fieldTop - postH; y <= fieldTop; y += 10) {
        ctx.beginPath(); ctx.moveTo((w - goalW) / 2, y); ctx.lineTo((w + goalW) / 2, y); ctx.stroke();
      }

      // StuCred banner
      ctx.fillStyle = 'rgba(255,107,53,0.3)';
      ctx.fillRect((w - goalW) / 2 + 15, fieldTop - postH - 24, goalW - 30, 20);
      ctx.fillStyle = '#f7931e'; ctx.font = 'bold 12px Montserrat';
      ctx.textAlign = 'center'; ctx.fillText('STUCRED', w / 2, fieldTop - postH - 10);
    };

    const loop = () => {
      const w = canvas.width, h = canvas.height;
      const centerX = w / 2;
      const goalW = w * 0.72;
      const goalLeft = (w - goalW) / 2;
      const goalRight = (w + goalW) / 2;
      const fieldTop = GOAL_TOP;

      ctx.clearRect(0, 0, w, h);
      drawField(w, h);

      const ball = ballRef.current;
      const keeper = keeperRef.current;
      const mouse = mouseRef.current;

      // ── Keeper idle sway ──
      if (keeper.state === 'idle' || keeper.state === 'anticipating') {
        keeper.movePhase += 0.035;
        const sway = Math.sin(keeper.movePhase) * 35;
        keeper.x = keeper.baseX + sway;
        keeper.y = fieldTop + GOAL_HEIGHT - 10 + Math.sin(keeper.movePhase * 2) * 2;
      }

      // ── Ball physics ──
      if (ball.active) {
        ball.x += ball.vx;
        ball.y += ball.vy;
        ball.vy += GRAVITY;
        ball.rotation += ball.vx * 0.06;
        ball.scale = Math.max(0.4, 1 - (fieldTop - ball.y) / 500);

        // ── Goal check ──
        if (ball.y < fieldTop && ball.y > fieldTop - 25 &&
          ball.x > goalLeft + 8 && ball.x < goalRight - 8 &&
          !ball.scored && !ball.saved) {
          ball.scored = true; ball.active = false;
          keeper.state = 'sad';
          goalsRef.current++;
          setGameState('result');
          setMessage('GOAL!!!');
          setShowConfetti(true);
          createParticles(ball.x, ball.y, '#ffd700', 50);
          onShot({ made: true, points: 100, multiplier: 1, message: 'GOAL!' });
          // Play goal sound
          playSound('goal');
          setTimeout(resetPositions, 2500);
        }

        // ── Miss check ──
        if ((ball.y < fieldTop - 60 || ball.x < -50 || ball.x > w + 50 || ball.y > h + 50) &&
          !ball.scored && !ball.saved) {
          ball.active = false;
          setGameState('result');
          setMessage(ball.y < fieldTop - 60 ? 'Over the bar!' : 'Wide!');
          onShot({ made: false, points: 0, multiplier: 1, message: 'Missed!' });
          // Play miss sound
          playSound('miss');
          setTimeout(resetPositions, 1800);
        }
      }

      // ── Keeper diving ──
      if (keeper.state === 'diving') {
        keeper.x += keeper.vx;
        keeper.y = fieldTop + GOAL_HEIGHT - 10 - Math.abs(keeper.x - centerX) * 0.15;

        // Collision - IMPROVED KEEPER BLOCKING (70:30 ratio)
        if (ball.active && !ball.saved && !ball.scored) {
          const dx = ball.x - keeper.x;
          const dy = ball.y - (keeper.y - keeper.height / 2);
          const dist = Math.sqrt(dx * dx + dy * dy);
          
          // Dynamic collision radius based on difficulty
          const baseBlockRadius = ball.radius + keeper.width * 0.55;
          const difficultyMultiplier = Math.min(1.4, 1.0 + goalsRef.current * 0.04);
          const blockRadius = baseBlockRadius * difficultyMultiplier;
          
          // Keeper dive extension - arms reach further
          const diveExtension = keeper.state === 'diving' ? 25 : 0;
          const totalBlockRadius = blockRadius + diveExtension;
          
          if (dist < totalBlockRadius) {
            ball.saved = true; ball.active = false;
            keeper.state = 'celebrating';
            setGameState('result');
            setMessage('SAVED!');
            createParticles(ball.x, ball.y, '#ff4444', 25);
            onShot({ made: false, points: 0, multiplier: 1, message: 'Saved!' });
            // Play save sound
            playSound('save');
            setTimeout(resetPositions, 1800);
          }
        }

        if (Math.abs(keeper.x - keeper.diveTarget) < 5) keeper.vx *= 0.85;
      }

      // ── Draw keeper ──
      ctx.save();
      ctx.translate(keeper.x, keeper.y);
      const kScale = 0.7 + (keeper.y - 100) / 400;
      ctx.scale(kScale, kScale);

      // Body
      const kg = ctx.createLinearGradient(0, -keeper.height, 0, 0);
      kg.addColorStop(0, keeper.state === 'sad' ? '#cc4422' : '#ff6b35');
      kg.addColorStop(1, keeper.state === 'sad' ? '#aa3311' : '#f7931e');
      ctx.fillStyle = kg;
      ctx.fillRect(-keeper.width / 2, -keeper.height, keeper.width, keeper.height);

      // Head
      ctx.fillStyle = '#fdbf60';
      ctx.beginPath(); ctx.arc(0, -keeper.height - 14, 15, 0, Math.PI * 2); ctx.fill();

      // Eyes tracking ball/cursor
      let lookX = mouse.x, lookY = mouse.y;
      if (ball.active) { lookX = ball.x; lookY = ball.y; }
      const eyeAngle = Math.atan2(lookY - keeper.y, lookX - keeper.x);
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(-7, -keeper.height - 16, 5, 0, Math.PI * 2); ctx.fill();
      ctx.beginPath(); ctx.arc(7, -keeper.height - 16, 5, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = '#222';
      ctx.beginPath(); ctx.arc(-7 + Math.cos(eyeAngle) * 2, -keeper.height - 16 + Math.sin(eyeAngle) * 2, 2.5, 0, Math.PI * 2); ctx.fill();
      ctx.beginPath(); ctx.arc(7 + Math.cos(eyeAngle) * 2, -keeper.height - 16 + Math.sin(eyeAngle) * 2, 2.5, 0, Math.PI * 2); ctx.fill();

      // Gloves
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(-keeper.width / 2 - 10, -keeper.height / 2, 11, 0, Math.PI * 2); ctx.fill();
      ctx.beginPath(); ctx.arc(keeper.width / 2 + 10, -keeper.height / 2, 11, 0, Math.PI * 2); ctx.fill();

      ctx.restore();

      // ── Draw 3D Football ──
      ctx.save();
      ctx.translate(ball.x, ball.y);
      ctx.scale(ball.scale, ball.scale);
      ctx.rotate(ball.rotation);

      // Shadow
      ctx.fillStyle = 'rgba(0,0,0,0.3)';
      ctx.beginPath();
      ctx.ellipse(0, ball.radius + 5, ball.radius * 0.7, ball.radius * 0.25, 0, 0, Math.PI * 2);
      ctx.fill();

      // Base sphere with 3D shading
      const sphereGrad = ctx.createRadialGradient(-5, -5, 0, 0, 0, ball.radius);
      sphereGrad.addColorStop(0, '#ffffff');
      sphereGrad.addColorStop(0.3, '#f0f0f0');
      sphereGrad.addColorStop(0.7, '#c0c0c0');
      sphereGrad.addColorStop(1, '#808080');
      ctx.fillStyle = sphereGrad;
      ctx.beginPath(); ctx.arc(0, 0, ball.radius, 0, Math.PI * 2); ctx.fill();

      // Classic football pattern - pentagons and hexagons
      const r = ball.radius;
      
      // Main pentagon (center)
      ctx.fillStyle = '#1a1a1a';
      ctx.beginPath();
      for (let i = 0; i < 5; i++) {
        const angle = (i * 2 * Math.PI / 5) - Math.PI / 2;
        const px = Math.cos(angle) * r * 0.4;
        const py = Math.sin(angle) * r * 0.4;
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath(); ctx.fill();
      ctx.strokeStyle = '#333'; ctx.lineWidth = 0.8; ctx.stroke();

      // Surrounding pentagons
      for (let j = 0; j < 5; j++) {
        const centerAngle = (j * 2 * Math.PI / 5) - Math.PI / 2;
        const cx = Math.cos(centerAngle) * r * 0.65;
        const cy = Math.sin(centerAngle) * r * 0.65;
        
        ctx.fillStyle = '#1a1a1a';
        ctx.beginPath();
        for (let i = 0; i < 5; i++) {
          const angle = (i * 2 * Math.PI / 5) - Math.PI / 2 + centerAngle * 0.3;
          const px = cx + Math.cos(angle) * r * 0.22;
          const py = cy + Math.sin(angle) * r * 0.22;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath(); ctx.fill();
        ctx.strokeStyle = '#333'; ctx.lineWidth = 0.6; ctx.stroke();
      }

      // Hexagon patches between pentagons
      for (let j = 0; j < 5; j++) {
        const angle1 = (j * 2 * Math.PI / 5) - Math.PI / 2;
        const angle2 = ((j + 1) * 2 * Math.PI / 5) - Math.PI / 2;
        const hx = Math.cos((angle1 + angle2) / 2) * r * 0.82;
        const hy = Math.sin((angle1 + angle2) / 2) * r * 0.82;
        
        ctx.fillStyle = '#f5f5f5';
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const a = (i * Math.PI / 3) + (angle1 + angle2) / 2;
          const px = hx + Math.cos(a) * r * 0.18;
          const py = hy + Math.sin(a) * r * 0.18;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath(); ctx.fill();
        ctx.strokeStyle = '#ccc'; ctx.lineWidth = 0.5; ctx.stroke();
      }

      // Highlight
      ctx.fillStyle = 'rgba(255,255,255,0.4)';
      ctx.beginPath(); ctx.arc(-r * 0.3, -r * 0.3, r * 0.25, 0, Math.PI * 2); ctx.fill();

      ctx.restore();

      // ── Aim cursor / target ──
      if (gameState === 'aiming') {
        const tx = ball.targetX;
        const ty = ball.targetY;

        // Crosshair
        ctx.strokeStyle = 'rgba(255,255,255,0.6)';
        ctx.lineWidth = 2;
        const crossSize = 12;
        ctx.beginPath();
        ctx.moveTo(tx - crossSize, ty); ctx.lineTo(tx + crossSize, ty);
        ctx.moveTo(tx, ty - crossSize); ctx.lineTo(tx, ty + crossSize);
        ctx.stroke();

        // Circle
        ctx.strokeStyle = 'rgba(255,255,255,0.4)';
        ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(tx, ty, 18, 0, Math.PI * 2); ctx.stroke();

        // Dotted line from ball to target
        ctx.strokeStyle = 'rgba(255,255,255,0.25)';
        ctx.lineWidth = 1.5;
        ctx.setLineDash([4, 4]);
        ctx.beginPath(); ctx.moveTo(ball.x, ball.y); ctx.lineTo(tx, ty); ctx.stroke();
        ctx.setLineDash([]);

        // Target label
        ctx.fillStyle = 'rgba(255,255,255,0.5)';
        ctx.font = '11px Montserrat';
        ctx.textAlign = 'center';
        ctx.fillText('CLICK TO SHOOT', tx, ty + 35);
      }

      // ── Particles ──
      particlesRef.current = particlesRef.current.filter(p => {
        p.x += p.vx; p.y += p.vy; p.vy += 0.15; p.life -= 0.025;
        if (p.life > 0) {
          ctx.globalAlpha = p.life; ctx.fillStyle = p.color;
          ctx.beginPath(); ctx.arc(p.x, p.y, p.size * p.life, 0, Math.PI * 2); ctx.fill();
          ctx.globalAlpha = 1; return true;
        }
        return false;
      });

      // ── Message ──
      if (message) {
        ctx.fillStyle = message.includes('GOAL') ? '#ffd700' : message.includes('SAVED') ? '#ff6666' : '#fff';
        ctx.font = 'bold 40px Montserrat'; ctx.textAlign = 'center';
        ctx.shadowColor = 'rgba(0,0,0,0.9)'; ctx.shadowBlur = 12;
        ctx.fillText(message, centerX, h / 2);
        ctx.shadowBlur = 0;
      }

      // ── Confetti ──
      if (showConfetti) {
        for (let i = 0; i < 80; i++) {
          const x = Math.random() * w, y = Math.random() * h * 0.6;
          const sz = Math.random() * 6 + 2;
          ctx.fillStyle = `hsl(${Math.random() * 360},100%,60%)`;
          ctx.fillRect(x, y, sz, sz);
        }
      }

      // ── Instructions ──
      if (gameState === 'aiming') {
        ctx.fillStyle = 'rgba(255,255,255,0.6)';
        ctx.font = '13px Montserrat'; ctx.textAlign = 'center';
        ctx.fillText('Move cursor to aim, CLICK to shoot!', centerX, h - 25);
      }

      animRef.current = requestAnimationFrame(loop);
    };

    animRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animRef.current);
  }, [gameState, message, showConfetti, createParticles, resetPositions, onShot]);

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', background: '#0a1628', position: 'relative', overflow: 'hidden' }}>
      {/* HUD */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 20px', background: 'rgba(0,0,0,0.85)', zIndex: 10 }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 900, color: '#f7931e' }}>{score}</div>
          <div style={{ fontSize: '10px', color: 'rgba(255,255,255,0.6)', textTransform: 'uppercase' }}>Score</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 900, color: '#f7931e' }}>{timeRemaining}</div>
          <div style={{ fontSize: '10px', color: 'rgba(255,255,255,0.6)', textTransform: 'uppercase' }}>Time</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '22px', fontWeight: 900, color: '#f7931e' }}>{shotsMade}/{shotsTaken}</div>
          <div style={{ fontSize: '10px', color: 'rgba(255,255,255,0.6)', textTransform: 'uppercase' }}>Goals</div>
        </div>
      </div>

      {/* Canvas */}
      <div ref={containerRef} style={{ flex: 1, position: 'relative' }}>
        <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block', touchAction: 'none', cursor: gameState === 'aiming' ? 'crosshair' : 'default' }} />
      </div>
    </div>
  );
}
