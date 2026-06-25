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

// Game constants
const GRAVITY = 0.25;
const BALL_RADIUS = 14;
const POWER_MAX = 22;
const POWER_MIN = 6;

interface Ball {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  rotation: number;
  active: boolean;
  scored: boolean;
  saved: boolean;
  scale: number;
}

interface Goalkeeper {
  x: number;
  y: number;
  width: number;
  height: number;
  vx: number;
  state: 'idle' | 'diving' | 'celebrating';
  diveTarget: number;
}

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  color: string;
  size: number;
}

export default function GameScreen({
  gameConfig: _gameConfig,
  timeRemaining,
  isPlaying,
  score,
  shotsTaken,
  shotsMade,
  currentStreak: _currentStreak,
  onShot,
  onGameOver,
  setTimeRemaining,
  setIsPlaying,
}: GameScreenProps) {
  void _gameConfig;
  void _currentStreak;

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [gameState, setGameState] = useState<'aiming' | 'charging' | 'shooting' | 'result'>('aiming');
  const [_power, setPower] = useState(0);
  void _power;
  const [message, setMessage] = useState('');
  const [showConfetti, setShowConfetti] = useState(false);

  const ballRef = useRef<Ball>({
    x: 0, y: 0, vx: 0, vy: 0, radius: BALL_RADIUS,
    rotation: 0, active: false, scored: false, saved: false, scale: 1,
  });

  const keeperRef = useRef<Goalkeeper>({
    x: 0, y: 0, width: 50, height: 70, vx: 0, state: 'idle', diveTarget: 0,
  });

  const particlesRef = useRef<Particle[]>([]);
  const animRef = useRef<number>(0);
  const powerRef = useRef(0);
  const chargingRef = useRef(false);
  const aimRef = useRef({ angle: -Math.PI / 2, power: 0 });
  const touchRef = useRef({ startX: 0, startY: 0, isDragging: false });

  // Canvas sizing
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

  // Timer
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
    for (let i = 0; i < count; i++) {
      particlesRef.current.push({
        x, y,
        vx: (Math.random() - 0.5) * 12,
        vy: (Math.random() - 0.5) * 12 - 4,
        life: 1,
        color,
        size: Math.random() * 5 + 2,
      });
    }
  }, []);

  const resetPositions = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const w = canvas.width;
    const h = canvas.height;

    ballRef.current = {
      x: w / 2,
      y: h - 80,
      vx: 0, vy: 0,
      radius: BALL_RADIUS,
      rotation: 0,
      active: false,
      scored: false,
      saved: false,
      scale: 1,
    };

    keeperRef.current = {
      x: w / 2,
      y: 140,
      width: 50,
      height: 70,
      vx: 0,
      state: 'idle',
      diveTarget: w / 2,
    };

    setGameState('aiming');
    powerRef.current = 0;
    setPower(0);
    setMessage('');
    setShowConfetti(false);
    chargingRef.current = false;
  }, []);

  // Touch / Mouse handlers
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const getPos = (e: MouseEvent | TouchEvent) => {
      const rect = canvas.getBoundingClientRect();
      const cx = 'touches' in e ? e.touches[0]?.clientX ?? e.changedTouches[0]?.clientX : e.clientX;
      const cy = 'touches' in e ? e.touches[0]?.clientY ?? e.changedTouches[0]?.clientY : e.clientY;
      return { x: (cx || 0) - rect.left, y: (cy || 0) - rect.top };
    };

    const onStart = (e: MouseEvent | TouchEvent) => {
      if (gameState !== 'aiming') return;
      e.preventDefault();
      const pos = getPos(e);
      touchRef.current = { startX: pos.x, startY: pos.y, isDragging: true };
      chargingRef.current = true;
      powerRef.current = 0;
      setGameState('charging');
    };

    const onMove = (e: MouseEvent | TouchEvent) => {
      if (!touchRef.current.isDragging || gameState !== 'charging') return;
      e.preventDefault();
      const pos = getPos(e);
      const ball = ballRef.current;

      // Aim angle from ball to touch
      const dx = pos.x - ball.x;
      const dy = pos.y - ball.y;
      aimRef.current.angle = Math.atan2(dy, dx);

      // Power based on drag distance (clamped)
      const dist = Math.min(Math.sqrt(dx * dx + dy * dy) / 3, POWER_MAX);
      powerRef.current = Math.max(dist, POWER_MIN);
      setPower(powerRef.current);
    };

    const onEnd = (e: MouseEvent | TouchEvent) => {
      if (!touchRef.current.isDragging || gameState !== 'charging') return;
      e.preventDefault();
      touchRef.current.isDragging = false;
      chargingRef.current = false;

      const ball = ballRef.current;
      const pwr = Math.max(powerRef.current, POWER_MIN);
      const angle = aimRef.current.angle;

      // Only allow upward shots
      if (angle > -0.2) {
        setGameState('aiming');
        setPower(0);
        setMessage('Aim higher!');
        setTimeout(() => setMessage(''), 1000);
        return;
      }

      ball.vx = Math.cos(angle) * pwr;
      ball.vy = Math.sin(angle) * pwr;
      ball.active = true;

      // Keeper AI
      const keeper = keeperRef.current;
      const canvas = canvasRef.current;
      if (canvas) {
        const centerX = canvas.width / 2;
        const goalW = canvas.width * 0.7;
        const goalLeft = centerX - goalW / 2;
        const goalRight = centerX + goalW / 2;

        // Predict where ball will cross keeper's Y
        const timeToKeeper = (keeper.y - ball.y) / ball.vy;
        const ballAtKeeperX = ball.x + ball.vx * timeToKeeper;

        let targetX = ballAtKeeperX;
        // Add randomness
        if (Math.random() < 0.35) {
          targetX += (Math.random() - 0.5) * 120;
        }
        targetX = Math.max(goalLeft + 30, Math.min(goalRight - 30, targetX));

        keeper.diveTarget = targetX;
        keeper.state = 'diving';
        keeper.vx = (targetX - keeper.x) / 12;
      }

      setGameState('shooting');
      setPower(0);
      powerRef.current = 0;
    };

    canvas.addEventListener('mousedown', onStart);
    canvas.addEventListener('mousemove', onMove);
    canvas.addEventListener('mouseup', onEnd);
    canvas.addEventListener('touchstart', onStart, { passive: false });
    canvas.addEventListener('touchmove', onMove, { passive: false });
    canvas.addEventListener('touchend', onEnd);

    return () => {
      canvas.removeEventListener('mousedown', onStart);
      canvas.removeEventListener('mousemove', onMove);
      canvas.removeEventListener('mouseup', onEnd);
      canvas.removeEventListener('touchstart', onStart);
      canvas.removeEventListener('touchmove', onMove);
      canvas.removeEventListener('touchend', onEnd);
    };
  }, [gameState]);

  // Game loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const drawField = (w: number, h: number) => {
      // Sky
      const sky = ctx.createLinearGradient(0, 0, 0, h * 0.4);
      sky.addColorStop(0, '#0d2137');
      sky.addColorStop(1, '#1a4a6e');
      ctx.fillStyle = sky;
      ctx.fillRect(0, 0, w, h * 0.4);

      // Stadium stands
      ctx.fillStyle = '#080e1a';
      ctx.fillRect(0, 30, w, 60);
      for (let i = 0; i < w; i += 6) {
        for (let j = 35; j < 80; j += 8) {
          ctx.fillStyle = `hsl(${200 + Math.random() * 40}, 60%, ${30 + Math.random() * 25}%)`;
          ctx.fillRect(i, j, 4, 5);
        }
      }

      // Field - perspective trapezoid
      const fieldTop = 120;
      const fieldBottom = h;
      const goalW = w * 0.7;

      // Grass
      const grass = ctx.createLinearGradient(0, fieldTop, 0, fieldBottom);
      grass.addColorStop(0, '#2d6b32');
      grass.addColorStop(1, '#3d8b42');
      ctx.fillStyle = grass;
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop);
      ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.lineTo(w, fieldBottom);
      ctx.lineTo(0, fieldBottom);
      ctx.closePath();
      ctx.fill();

      // Field stripes
      ctx.save();
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop);
      ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.lineTo(w, fieldBottom);
      ctx.lineTo(0, fieldBottom);
      ctx.closePath();
      ctx.clip();

      for (let i = -w; i < w * 2; i += 40) {
        ctx.fillStyle = 'rgba(255,255,255,0.04)';
        ctx.fillRect(i, fieldTop, 20, fieldBottom - fieldTop);
      }
      ctx.restore();

      // Goal line
      ctx.strokeStyle = 'rgba(255,255,255,0.8)';
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop);
      ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.stroke();

      // Penalty box lines (perspective)
      const boxW = goalW * 0.6;
      const boxH = 80;
      ctx.strokeStyle = 'rgba(255,255,255,0.6)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo((w - boxW) / 2, fieldTop + boxH);
      ctx.lineTo((w - boxW) / 2, fieldTop);
      ctx.lineTo((w + boxW) / 2, fieldTop);
      ctx.lineTo((w + boxW) / 2, fieldTop + boxH);
      ctx.stroke();

      // Penalty spot
      ctx.fillStyle = '#fff';
      ctx.beginPath();
      ctx.arc(w / 2, fieldTop + boxH + 40, 3, 0, Math.PI * 2);
      ctx.fill();

      // Goal posts
      const postH = 70;
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.moveTo((w - goalW) / 2, fieldTop);
      ctx.lineTo((w - goalW) / 2, fieldTop - postH);
      ctx.lineTo((w + goalW) / 2, fieldTop - postH);
      ctx.lineTo((w + goalW) / 2, fieldTop);
      ctx.stroke();

      // Goal net
      ctx.strokeStyle = 'rgba(255,255,255,0.25)';
      ctx.lineWidth = 1;
      for (let x = (w - goalW) / 2; x <= (w + goalW) / 2; x += 12) {
        ctx.beginPath();
        ctx.moveTo(x, fieldTop - postH);
        ctx.lineTo(x, fieldTop);
        ctx.stroke();
      }
      for (let y = fieldTop - postH; y <= fieldTop; y += 12) {
        ctx.beginPath();
        ctx.moveTo((w - goalW) / 2, y);
        ctx.lineTo((w + goalW) / 2, y);
        ctx.stroke();
      }

      // StuCred branding on banners
      ctx.fillStyle = 'rgba(255, 107, 53, 0.3)';
      ctx.fillRect((w - goalW) / 2 + 20, fieldTop - postH - 25, goalW - 40, 20);
      ctx.fillStyle = '#f7931e';
      ctx.font = 'bold 12px Montserrat';
      ctx.textAlign = 'center';
      ctx.fillText('STUCRED', w / 2, fieldTop - postH - 11);
    };

    const loop = () => {
      const w = canvas.width;
      const h = canvas.height;
      const centerX = w / 2;
      const goalW = w * 0.7;
      const goalLeft = (w - goalW) / 2;
      const goalRight = (w + goalW) / 2;
      const fieldTop = 120;

      ctx.clearRect(0, 0, w, h);
      drawField(w, h);

      const ball = ballRef.current;
      const keeper = keeperRef.current;

      // Update ball physics
      if (ball.active) {
        ball.x += ball.vx;
        ball.y += ball.vy;
        ball.vy += GRAVITY;
        ball.rotation += ball.vx * 0.08;
        // Ball gets smaller as it goes further (perspective)
        ball.scale = Math.max(0.5, 1 - (fieldTop - ball.y) / 400);

        // Goal check
        if (ball.y < fieldTop && ball.y > fieldTop - 20 &&
            ball.x > goalLeft && ball.x < goalRight &&
            !ball.scored && !ball.saved) {
          ball.scored = true;
          ball.active = false;
          setGameState('result');
          setMessage('GOAL!!!');
          setShowConfetti(true);
          createParticles(ball.x, ball.y, '#ffd700', 40);

          onShot({ made: true, points: 100, multiplier: 1, message: 'GOAL!' });
          setTimeout(resetPositions, 2000);
        }

        // Miss check
        if (ball.y < fieldTop - 50 || ball.x < -50 || ball.x > w + 50 || ball.y > h + 50) {
          if (!ball.scored && !ball.saved) {
            ball.active = false;
            setGameState('result');
            setMessage(ball.y < fieldTop - 50 ? 'Over the bar!' : 'Missed!');
            onShot({ made: false, points: 0, multiplier: 1, message: 'Missed!' });
            setTimeout(resetPositions, 1500);
          }
        }
      }

      // Update keeper
      if (keeper.state === 'diving') {
        keeper.x += keeper.vx;
        // Slight upward arc when diving
        keeper.y = 140 - Math.abs(keeper.x - centerX) * 0.15;

        // Ball-keeper collision
        if (ball.active && !ball.saved && !ball.scored) {
          const dx = ball.x - keeper.x;
          const dy = ball.y - (keeper.y - keeper.height / 2);
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < ball.radius + keeper.width * 0.6) {
            ball.saved = true;
            ball.active = false;
            keeper.state = 'celebrating';
            setGameState('result');
            setMessage('SAVED!');
            createParticles(ball.x, ball.y, '#ff4444', 20);
            onShot({ made: false, points: 0, multiplier: 1, message: 'Saved!' });
            setTimeout(resetPositions, 1500);
          }
        }

        if (Math.abs(keeper.x - keeper.diveTarget) < 3) {
          keeper.vx *= 0.9;
        }
      }

      // Draw keeper
      ctx.save();
      ctx.translate(keeper.x, keeper.y);
      const kScale = 0.8 + (keeper.y - 100) / 300;
      ctx.scale(kScale, kScale);

      // Body
      const kg = ctx.createLinearGradient(0, -keeper.height, 0, 0);
      kg.addColorStop(0, '#ff6b35');
      kg.addColorStop(1, '#f7931e');
      ctx.fillStyle = kg;
      ctx.fillRect(-keeper.width / 2, -keeper.height, keeper.width, keeper.height);

      // Head
      ctx.fillStyle = '#fdbf60';
      ctx.beginPath();
      ctx.arc(0, -keeper.height - 12, 14, 0, Math.PI * 2);
      ctx.fill();

      // Gloves
      ctx.fillStyle = '#fff';
      ctx.beginPath();
      ctx.arc(-keeper.width / 2 - 8, -keeper.height / 2, 10, 0, Math.PI * 2);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(keeper.width / 2 + 8, -keeper.height / 2, 10, 0, Math.PI * 2);
      ctx.fill();

      ctx.restore();

      // Draw ball
      ctx.save();
      ctx.translate(ball.x, ball.y);
      ctx.scale(ball.scale, ball.scale);
      ctx.rotate(ball.rotation);

      // Shadow
      ctx.fillStyle = 'rgba(0,0,0,0.3)';
      ctx.beginPath();
      ctx.ellipse(0, ball.radius + 4, ball.radius * 0.7, ball.radius * 0.25, 0, 0, Math.PI * 2);
      ctx.fill();

      // Ball
      const bg = ctx.createRadialGradient(-4, -4, 0, 0, 0, ball.radius);
      bg.addColorStop(0, '#fff');
      bg.addColorStop(0.6, '#e0e0e0');
      bg.addColorStop(1, '#999');
      ctx.fillStyle = bg;
      ctx.beginPath();
      ctx.arc(0, 0, ball.radius, 0, Math.PI * 2);
      ctx.fill();

      // Pattern
      ctx.strokeStyle = '#222';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(0, 0, ball.radius * 0.55, 0, Math.PI * 2);
      ctx.stroke();
      for (let i = 0; i < 5; i++) {
        const a = (i / 5) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(Math.cos(a) * ball.radius * 0.55, Math.sin(a) * ball.radius * 0.55);
        ctx.stroke();
      }
      ctx.restore();

      // Aim guide (when charging)
      if (gameState === 'charging') {
        const ball = ballRef.current;
        const angle = aimRef.current.angle;
        const pwr = powerRef.current;

        // Trajectory preview
        ctx.strokeStyle = `rgba(255, 255, 255, ${0.2 + (pwr / POWER_MAX) * 0.4})`;
        ctx.lineWidth = 2;
        ctx.setLineDash([6, 6]);
        ctx.beginPath();
        ctx.moveTo(ball.x, ball.y);

        let simX = ball.x;
        let simY = ball.y;
        let simVX = Math.cos(angle) * pwr;
        let simVY = Math.sin(angle) * pwr;

        for (let i = 0; i < 30; i++) {
          simX += simVX;
          simY += simVY;
          simVY += GRAVITY;
          ctx.lineTo(simX, simY);
          if (simY < fieldTop) break;
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // Arrow at end
        ctx.fillStyle = `rgba(255, 255, 255, ${0.4 + (pwr / POWER_MAX) * 0.4})`;
        ctx.beginPath();
        ctx.arc(simX, simY, 4, 0, Math.PI * 2);
        ctx.fill();

        // Power bar at bottom
        const barW = 120;
        const barH = 12;
        const barX = centerX - barW / 2;
        const barY = h - 50;

        ctx.fillStyle = 'rgba(0,0,0,0.6)';
        ctx.fillRect(barX, barY, barW, barH);

        const pct = Math.min(pwr / POWER_MAX, 1);
        const col = pct < 0.4 ? '#00ff88' : pct < 0.7 ? '#ffcc00' : '#ff4444';
        ctx.fillStyle = col;
        ctx.fillRect(barX, barY, barW * pct, barH);

        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 1;
        ctx.strokeRect(barX, barY, barW, barH);

        ctx.fillStyle = '#fff';
        ctx.font = 'bold 11px Montserrat';
        ctx.textAlign = 'center';
        ctx.fillText('DRAG DISTANCE = POWER', centerX, barY - 8);
      }

      // Particles
      particlesRef.current = particlesRef.current.filter(p => {
        p.x += p.vx;
        p.y += p.vy;
        p.vy += 0.15;
        p.life -= 0.025;
        if (p.life > 0) {
          ctx.globalAlpha = p.life;
          ctx.fillStyle = p.color;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size * p.life, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
          return true;
        }
        return false;
      });

      // Message
      if (message) {
        ctx.fillStyle = message.includes('GOAL') ? '#ffd700' : message.includes('SAVED') ? '#ff4444' : '#fff';
        ctx.font = 'bold 36px Montserrat';
        ctx.textAlign = 'center';
        ctx.shadowColor = 'rgba(0,0,0,0.8)';
        ctx.shadowBlur = 8;
        ctx.fillText(message, centerX, h / 2);
        ctx.shadowBlur = 0;
      }

      // Confetti
      if (showConfetti) {
        for (let i = 0; i < 60; i++) {
          const x = Math.random() * w;
          const y = Math.random() * h * 0.6;
          const sz = Math.random() * 5 + 2;
          ctx.fillStyle = `hsl(${Math.random() * 360}, 100%, 60%)`;
          ctx.fillRect(x, y, sz, sz);
        }
      }

      // Instruction
      if (gameState === 'aiming') {
        ctx.fillStyle = 'rgba(255,255,255,0.7)';
        ctx.font = '14px Montserrat';
        ctx.textAlign = 'center';
        ctx.fillText('Drag back from ball to aim & power up, release to shoot!', centerX, h - 20);
      }

      animRef.current = requestAnimationFrame(loop);
    };

    animRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animRef.current);
  }, [gameState, message, showConfetti, createParticles, resetPositions, onShot]);

  return (
    <div style={{
      width: '100%', height: '100%', display: 'flex', flexDirection: 'column',
      background: '#0a1628', position: 'relative', overflow: 'hidden',
    }}>
      {/* HUD */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '10px 20px', background: 'rgba(0,0,0,0.8)', zIndex: 10,
      }}>
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
        <canvas
          ref={canvasRef}
          style={{ width: '100%', height: '100%', display: 'block', touchAction: 'none' }}
        />
      </div>
    </div>
  );
}
