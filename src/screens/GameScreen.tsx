import { useEffect, useRef, useState, useCallback } from 'react';
import type { GameConfig, ShotResult } from '../types/game';

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
      const targetX = pos.x;
      keeper.diveSpeed = Math.min(2.5, 1.2 + goalsRef.current * 0.15);

      // Keeper reaction: moves toward predicted landing with some error
      setTimeout(() => {
        if (keeper.state === 'anticipating') {
          keeper.state = 'diving';
          // Prediction accuracy decreases as player scores more
          const accuracy = Math.max(0.3, 1 - goalsRef.current * 0.08);
          let predictedX = targetX;
          if (Math.random() > accuracy) {
            predictedX += (Math.random() - 0.5) * 100;
          }
          keeper.vx = (predictedX - keeper.x) / (keeper.reactionDelay / keeper.diveSpeed);
        }
      }, 150 + Math.random() * 200);

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
      ctx.lineTo((w + boxW) / 2, fieldTop);
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
          setTimeout(resetPositions, 2500);
        }

        // ── Miss check ──
        if ((ball.y < fieldTop - 60 || ball.x < -50 || ball.x > w + 50 || ball.y > h + 50) &&
          !ball.scored && !ball.saved) {
          ball.active = false;
          setGameState('result');
          setMessage(ball.y < fieldTop - 60 ? 'Over the bar!' : 'Wide!');
          onShot({ made: false, points: 0, multiplier: 1, message: 'Missed!' });
          setTimeout(resetPositions, 1800);
        }
      }

      // ── Keeper diving ──
      if (keeper.state === 'diving') {
        keeper.x += keeper.vx;
        keeper.y = fieldTop + GOAL_HEIGHT - 10 - Math.abs(keeper.x - centerX) * 0.15;

        // Collision
        if (ball.active && !ball.saved && !ball.scored) {
          const dx = ball.x - keeper.x;
          const dy = ball.y - (keeper.y - keeper.height / 2);
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < ball.radius + keeper.width * 0.5) {
            ball.saved = true; ball.active = false;
            keeper.state = 'celebrating';
            setGameState('result');
            setMessage('SAVED!');
            createParticles(ball.x, ball.y, '#ff4444', 25);
            onShot({ made: false, points: 0, multiplier: 1, message: 'Saved!' });
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

      // ── Draw ball ──
      ctx.save();
      ctx.translate(ball.x, ball.y);
      ctx.scale(ball.scale, ball.scale);
      ctx.rotate(ball.rotation);

      ctx.fillStyle = 'rgba(0,0,0,0.3)';
      ctx.beginPath();
      ctx.ellipse(0, ball.radius + 5, ball.radius * 0.7, ball.radius * 0.25, 0, 0, Math.PI * 2); ctx.fill();

      const bg = ctx.createRadialGradient(-4, -4, 0, 0, 0, ball.radius);
      bg.addColorStop(0, '#fff'); bg.addColorStop(0.6, '#e8e8e8'); bg.addColorStop(1, '#999');
      ctx.fillStyle = bg;
      ctx.beginPath(); ctx.arc(0, 0, ball.radius, 0, Math.PI * 2); ctx.fill();

      ctx.strokeStyle = '#222'; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(0, 0, ball.radius * 0.55, 0, Math.PI * 2); ctx.stroke();
      for (let i = 0; i < 5; i++) {
        const a = (i / 5) * Math.PI * 2;
        ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(Math.cos(a) * ball.radius * 0.55, Math.sin(a) * ball.radius * 0.55); ctx.stroke();
      }
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
