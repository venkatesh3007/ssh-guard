import React, { useEffect, useRef, useState, useCallback } from 'react';
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
const GRAVITY = 0.4;
const BALL_RADIUS = 12;
const GOAL_WIDTH = 280;
const GOAL_HEIGHT = 140;
const GOAL_Y = 100;
const GROUND_Y = 400;
const BALL_START_X = 200;
const BALL_START_Y = 350;
const POWER_MAX = 25;
const POWER_MIN = 8;

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
}

interface Goalkeeper {
  x: number;
  y: number;
  width: number;
  height: number;
  vx: number;
  vy: number;
  state: 'idle' | 'diving' | 'celebrating' | 'sad';
  diveTarget: number;
  diveDirection: 'left' | 'center' | 'right';
}

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  maxLife: number;
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
  // Use the prefixed variables to avoid TS errors
  void _gameConfig;
  void _currentStreak;
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [gameState, setGameState] = useState<'aiming' | 'charging' | 'shooting' | 'result' | 'resetting'>('aiming');
  const [power, setPower] = useState(0);
  const [aimAngle, setAimAngle] = useState(-Math.PI / 2);
  const [message, setMessage] = useState('Drag to aim, hold to power up!');
  const [showConfetti, setShowConfetti] = useState(false);
  
  const ballRef = useRef<Ball>({
    x: BALL_START_X,
    y: BALL_START_Y,
    vx: 0,
    vy: 0,
    radius: BALL_RADIUS,
    rotation: 0,
    active: false,
    scored: false,
    saved: false,
  });
  
  const keeperRef = useRef<Goalkeeper>({
    x: 200,
    y: GOAL_Y + GOAL_HEIGHT - 40,
    width: 40,
    height: 60,
    vx: 0,
    vy: 0,
    state: 'idle',
    diveTarget: 200,
    diveDirection: 'center',
  });
  
  const particlesRef = useRef<Particle[]>([]);
  const animationRef = useRef<number>(0);
  const powerIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mouseRef = useRef({ x: 0, y: 0, isDown: false });
  const chargeStartRef = useRef(0);

  // Initialize canvas size
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const resize = () => {
      const container = containerRef.current;
      if (!container) return;
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
    };
    
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, []);

  // Timer countdown
  useEffect(() => {
    if (!isPlaying || timeRemaining <= 0) return;
    
    const timer = setInterval(() => {
      setTimeRemaining(timeRemaining - 1);
    }, 1000);
    
    return () => clearInterval(timer);
  }, [isPlaying, timeRemaining, setTimeRemaining]);

  // End game when time runs out
  useEffect(() => {
    if (timeRemaining <= 0 && isPlaying) {
      setIsPlaying(false);
      onGameOver(score);
    }
  }, [timeRemaining, isPlaying, score, onGameOver, setIsPlaying]);

  // Create particles
  const createParticles = useCallback((x: number, y: number, color: string, count: number) => {
    for (let i = 0; i < count; i++) {
      particlesRef.current.push({
        x,
        y,
        vx: (Math.random() - 0.5) * 10,
        vy: (Math.random() - 0.5) * 10 - 5,
        life: 1,
        maxLife: 1,
        color,
        size: Math.random() * 4 + 2,
      });
    }
  }, []);

  // Reset ball and keeper
  const resetPositions = useCallback(() => {
    ballRef.current = {
      x: BALL_START_X,
      y: BALL_START_Y,
      vx: 0,
      vy: 0,
      radius: BALL_RADIUS,
      rotation: 0,
      active: false,
      scored: false,
      saved: false,
    };
    
    keeperRef.current = {
      x: canvasRef.current ? canvasRef.current.width / 2 : 200,
      y: GOAL_Y + GOAL_HEIGHT - 40,
      width: 40,
      height: 60,
      vx: 0,
      vy: 0,
      state: 'idle',
      diveTarget: canvasRef.current ? canvasRef.current.width / 2 : 200,
      diveDirection: 'center',
    };
    
    setGameState('aiming');
    setPower(0);
    setMessage('Drag to aim, hold to power up!');
    setShowConfetti(false);
  }, []);

  // Handle mouse/touch events
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const getPos = (e: MouseEvent | TouchEvent) => {
      const rect = canvas.getBoundingClientRect();
      const clientX = 'touches' in e ? e.touches[0]?.clientX : e.clientX;
      const clientY = 'touches' in e ? e.touches[0]?.clientY : e.clientY;
      return {
        x: (clientX || 0) - rect.left,
        y: (clientY || 0) - rect.top,
      };
    };

    const handleStart = (e: MouseEvent | TouchEvent) => {
      if (gameState !== 'aiming') return;
      e.preventDefault();
      const pos = getPos(e);
      mouseRef.current = { x: pos.x, y: pos.y, isDown: true };
      chargeStartRef.current = Date.now();
      setGameState('charging');
      
      // Start power charging
      powerIntervalRef.current = setInterval(() => {
        setPower(prev => {
          const newPower = Math.min(prev + 0.5, POWER_MAX);
          return newPower;
        });
      }, 50);
    };

    const handleMove = (e: MouseEvent | TouchEvent) => {
      if (!mouseRef.current.isDown || gameState !== 'charging') return;
      e.preventDefault();
      const pos = getPos(e);
      mouseRef.current = { ...mouseRef.current, x: pos.x, y: pos.y };
      
      // Calculate aim angle
      const ball = ballRef.current;
      const dx = pos.x - ball.x;
      const dy = pos.y - ball.y;
      const angle = Math.atan2(dy, dx);
      setAimAngle(angle);
    };

    const handleEnd = (e: MouseEvent | TouchEvent) => {
      if (!mouseRef.current.isDown || gameState !== 'charging') return;
      e.preventDefault();
      mouseRef.current.isDown = false;
      
      if (powerIntervalRef.current) {
        clearInterval(powerIntervalRef.current);
      }
      
      // Shoot the ball
      const currentPower = Math.max(power, POWER_MIN);
      const ball = ballRef.current;
      ball.vx = Math.cos(aimAngle) * currentPower;
      ball.vy = Math.sin(aimAngle) * currentPower;
      ball.active = true;
      
      // Goalkeeper AI - decide dive direction based on ball trajectory
      const keeper = keeperRef.current;
      const predictedX = ball.x + ball.vx * 20;
      
      if (predictedX < canvas.width / 2 - 40) {
        keeper.diveDirection = 'left';
        keeper.diveTarget = canvas.width / 2 - 80;
      } else if (predictedX > canvas.width / 2 + 40) {
        keeper.diveDirection = 'right';
        keeper.diveTarget = canvas.width / 2 + 80;
      } else {
        keeper.diveDirection = 'center';
        keeper.diveTarget = canvas.width / 2;
      }
      
      // Add some randomness to keeper
      if (Math.random() < 0.3) {
        keeper.diveDirection = ['left', 'center', 'right'][Math.floor(Math.random() * 3)] as 'left' | 'center' | 'right';
        keeper.diveTarget = keeper.diveDirection === 'left' ? canvas.width / 2 - 80 : 
                           keeper.diveDirection === 'right' ? canvas.width / 2 + 80 : canvas.width / 2;
      }
      
      keeper.state = 'diving';
      keeper.vx = (keeper.diveTarget - keeper.x) / 15;
      
      setGameState('shooting');
      setMessage('');
      setPower(0);
    };

    canvas.addEventListener('mousedown', handleStart);
    canvas.addEventListener('mousemove', handleMove);
    canvas.addEventListener('mouseup', handleEnd);
    canvas.addEventListener('touchstart', handleStart, { passive: false });
    canvas.addEventListener('touchmove', handleMove, { passive: false });
    canvas.addEventListener('touchend', handleEnd);

    return () => {
      canvas.removeEventListener('mousedown', handleStart);
      canvas.removeEventListener('mousemove', handleMove);
      canvas.removeEventListener('mouseup', handleEnd);
      canvas.removeEventListener('touchstart', handleStart);
      canvas.removeEventListener('touchmove', handleMove);
      canvas.removeEventListener('touchend', handleEnd);
      if (powerIntervalRef.current) clearInterval(powerIntervalRef.current);
    };
  }, [gameState, aimAngle, power]);

  // Game loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const gameLoop = () => {
      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      
      // Clear canvas
      ctx.clearRect(0, 0, width, height);
      
      // Draw sky
      const skyGradient = ctx.createLinearGradient(0, 0, 0, height);
      skyGradient.addColorStop(0, '#1a3a5c');
      skyGradient.addColorStop(0.5, '#2d5a87');
      skyGradient.addColorStop(1, '#4a7c59');
      ctx.fillStyle = skyGradient;
      ctx.fillRect(0, 0, width, height);
      
      // Draw crowd/stadium
      ctx.fillStyle = '#0a1628';
      ctx.fillRect(0, 0, width, 60);
      
      // Draw crowd dots
      for (let i = 0; i < width; i += 8) {
        for (let j = 10; j < 50; j += 8) {
          ctx.fillStyle = `hsl(${Math.random() * 60 + 200}, 70%, ${Math.random() * 30 + 40}%)`;
          ctx.fillRect(i, j, 4, 4);
        }
      }
      
      // Draw goal
      const goalLeft = centerX - GOAL_WIDTH / 2;
      const goalRight = centerX + GOAL_WIDTH / 2;
      
      // Goal posts
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.moveTo(goalLeft, GOAL_Y + GOAL_HEIGHT);
      ctx.lineTo(goalLeft, GOAL_Y);
      ctx.lineTo(goalRight, GOAL_Y);
      ctx.lineTo(goalRight, GOAL_Y + GOAL_HEIGHT);
      ctx.stroke();
      
      // Goal net
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
      ctx.lineWidth = 1;
      for (let x = goalLeft; x <= goalRight; x += 15) {
        ctx.beginPath();
        ctx.moveTo(x, GOAL_Y);
        ctx.lineTo(x, GOAL_Y + GOAL_HEIGHT);
        ctx.stroke();
      }
      for (let y = GOAL_Y; y <= GOAL_Y + GOAL_HEIGHT; y += 15) {
        ctx.beginPath();
        ctx.moveTo(goalLeft, y);
        ctx.lineTo(goalRight, y);
        ctx.stroke();
      }
      
      // Draw ground
      ctx.fillStyle = '#2d7d32';
      ctx.fillRect(0, GROUND_Y, width, height - GROUND_Y);
      
      // Grass texture
      ctx.strokeStyle = '#3d9d42';
      ctx.lineWidth = 1;
      for (let i = 0; i < width; i += 20) {
        ctx.beginPath();
        ctx.moveTo(i, GROUND_Y);
        ctx.lineTo(i + 10, GROUND_Y + 10);
        ctx.stroke();
      }
      
      // Penalty spot
      ctx.fillStyle = '#fff';
      ctx.beginPath();
      ctx.arc(centerX, GROUND_Y - 30, 4, 0, Math.PI * 2);
      ctx.fill();
      
      // Penalty area lines
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.6)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(centerX - 100, GROUND_Y);
      ctx.lineTo(centerX - 100, GROUND_Y - 60);
      ctx.lineTo(centerX + 100, GROUND_Y - 60);
      ctx.lineTo(centerX + 100, GROUND_Y);
      ctx.stroke();
      
      // Update and draw ball
      const ball = ballRef.current;
      if (ball.active) {
        ball.x += ball.vx;
        ball.y += ball.vy;
        ball.vy += GRAVITY;
        ball.rotation += ball.vx * 0.1;
        
        // Check goal collision
        if (ball.y < GOAL_Y + GOAL_HEIGHT && ball.y > GOAL_Y && 
            ball.x > goalLeft && ball.x < goalRight && !ball.scored && !ball.saved) {
          ball.scored = true;
          ball.active = false;
          setGameState('result');
          setMessage('GOAL!!!');
          setShowConfetti(true);
          createParticles(ball.x, ball.y, '#ffd700', 30);
          
          const result: ShotResult = {
            made: true,
            points: 100,
            multiplier: 1,
            message: 'GOAL!',
          };
          onShot(result);
          
          setTimeout(() => {
            resetPositions();
          }, 2000);
        }
        
        // Check if ball missed (went past goal)
        if (ball.y < GOAL_Y - 50 || ball.x < 0 || ball.x > width || ball.y > height) {
          if (!ball.scored && !ball.saved) {
            ball.active = false;
            setGameState('result');
            setMessage('Missed!');
            
            const result: ShotResult = {
              made: false,
              points: 0,
              multiplier: 1,
              message: 'Missed!',
            };
            onShot(result);
            
            setTimeout(() => {
              resetPositions();
            }, 1500);
          }
        }
      }
      
      // Draw ball
      ctx.save();
      ctx.translate(ball.x, ball.y);
      ctx.rotate(ball.rotation);
      
      // Ball shadow
      ctx.fillStyle = 'rgba(0, 0, 0, 0.3)';
      ctx.beginPath();
      ctx.ellipse(0, ball.radius + 5, ball.radius * 0.8, ball.radius * 0.3, 0, 0, Math.PI * 2);
      ctx.fill();
      
      // Ball body
      const ballGradient = ctx.createRadialGradient(-3, -3, 0, 0, 0, ball.radius);
      ballGradient.addColorStop(0, '#fff');
      ballGradient.addColorStop(0.7, '#ddd');
      ballGradient.addColorStop(1, '#999');
      ctx.fillStyle = ballGradient;
      ctx.beginPath();
      ctx.arc(0, 0, ball.radius, 0, Math.PI * 2);
      ctx.fill();
      
      // Ball pattern (pentagons)
      ctx.strokeStyle = '#333';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(0, 0, ball.radius * 0.6, 0, Math.PI * 2);
      ctx.stroke();
      
      ctx.restore();
      
      // Update and draw goalkeeper
      const keeper = keeperRef.current;
      if (keeper.state === 'diving') {
        keeper.x += keeper.vx;
        keeper.y -= Math.abs(keeper.vx) * 0.3;
        
        // Check collision with ball
        if (ball.active && !ball.saved && !ball.scored) {
          const dx = ball.x - keeper.x;
          const dy = ball.y - keeper.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          if (distance < ball.radius + keeper.width / 2) {
            ball.saved = true;
            ball.active = false;
            keeper.state = 'celebrating';
            setGameState('result');
            setMessage('SAVED!');
            createParticles(ball.x, ball.y, '#ff4444', 15);
            
            const result: ShotResult = {
              made: false,
              points: 0,
              multiplier: 1,
              message: 'Saved!',
            };
            onShot(result);
            
            setTimeout(() => {
              resetPositions();
            }, 1500);
          }
        }
        
        // Stop diving after reaching target
        if (Math.abs(keeper.x - keeper.diveTarget) < 5) {
          keeper.vx = 0;
        }
      }
      
      // Draw goalkeeper
      ctx.save();
      ctx.translate(keeper.x, keeper.y);
      
      // Keeper body
      const keeperGradient = ctx.createLinearGradient(0, -keeper.height, 0, 0);
      keeperGradient.addColorStop(0, '#ff6b35');
      keeperGradient.addColorStop(1, '#f7931e');
      ctx.fillStyle = keeperGradient;
      ctx.fillRect(-keeper.width / 2, -keeper.height, keeper.width, keeper.height);
      
      // Keeper head
      ctx.fillStyle = '#fdbf60';
      ctx.beginPath();
      ctx.arc(0, -keeper.height - 10, 12, 0, Math.PI * 2);
      ctx.fill();
      
      // Keeper gloves
      ctx.fillStyle = '#fff';
      ctx.beginPath();
      ctx.arc(-keeper.width / 2 - 5, -keeper.height / 2, 8, 0, Math.PI * 2);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(keeper.width / 2 + 5, -keeper.height / 2, 8, 0, Math.PI * 2);
      ctx.fill();
      
      ctx.restore();
      
      // Draw aim guide when charging
      if (gameState === 'charging') {
        ctx.strokeStyle = `rgba(255, 255, 255, ${0.3 + (power / POWER_MAX) * 0.5})`;
        ctx.lineWidth = 2;
        ctx.setLineDash([5, 5]);
        ctx.beginPath();
        ctx.moveTo(ball.x, ball.y);
        ctx.lineTo(
          ball.x + Math.cos(aimAngle) * 100,
          ball.y + Math.sin(aimAngle) * 100
        );
        ctx.stroke();
        ctx.setLineDash([]);
        
        // Power bar
        const barWidth = 100;
        const barHeight = 10;
        const barX = centerX - barWidth / 2;
        const barY = height - 40;
        
        ctx.fillStyle = 'rgba(0, 0, 0, 0.5)';
        ctx.fillRect(barX, barY, barWidth, barHeight);
        
        const powerPercent = power / POWER_MAX;
        const powerColor = powerPercent < 0.5 ? '#00ff00' : powerPercent < 0.8 ? '#ffff00' : '#ff0000';
        ctx.fillStyle = powerColor;
        ctx.fillRect(barX, barY, barWidth * powerPercent, barHeight);
        
        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 1;
        ctx.strokeRect(barX, barY, barWidth, barHeight);
        
        ctx.fillStyle = '#fff';
        ctx.font = '12px Montserrat';
        ctx.textAlign = 'center';
        ctx.fillText('POWER', centerX, barY - 5);
      }
      
      // Draw particles
      particlesRef.current = particlesRef.current.filter(p => {
        p.x += p.vx;
        p.y += p.vy;
        p.vy += 0.2;
        p.life -= 0.02;
        
        if (p.life > 0) {
          ctx.globalAlpha = p.life;
          ctx.fillStyle = p.color;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
          return true;
        }
        return false;
      });
      
      // Draw message
      if (message) {
        ctx.fillStyle = message.includes('GOAL') ? '#ffd700' : message.includes('Saved') ? '#ff4444' : '#fff';
        ctx.font = 'bold 32px Montserrat';
        ctx.textAlign = 'center';
        ctx.shadowColor = message.includes('GOAL') ? '#ffd700' : '#000';
        ctx.shadowBlur = 10;
        ctx.fillText(message, centerX, height / 2);
        ctx.shadowBlur = 0;
      }
      
      // Draw confetti
      if (showConfetti) {
        for (let i = 0; i < 50; i++) {
          const x = Math.random() * width;
          const y = Math.random() * height / 2;
          const size = Math.random() * 6 + 2;
          const color = `hsl(${Math.random() * 360}, 100%, 50%)`;
          
          ctx.fillStyle = color;
          ctx.fillRect(x, y, size, size);
        }
      }
      
      animationRef.current = requestAnimationFrame(gameLoop);
    };
    
    animationRef.current = requestAnimationFrame(gameLoop);
    
    return () => {
      cancelAnimationFrame(animationRef.current);
    };
  }, [gameState, aimAngle, power, message, showConfetti, createParticles, resetPositions, onShot]);

  const containerStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    background: '#0a1628',
    position: 'relative',
    overflow: 'hidden',
  };

  const hudStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '8px 16px',
    background: 'rgba(0, 0, 0, 0.7)',
    zIndex: 10,
  };

  const hudItemStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
  };

  const hudValueStyle: React.CSSProperties = {
    fontSize: '20px',
    fontWeight: 900,
    color: '#f7931e',
  };

  const hudLabelStyle: React.CSSProperties = {
    fontSize: '10px',
    fontWeight: 600,
    color: 'rgba(255, 255, 255, 0.7)',
    textTransform: 'uppercase',
    letterSpacing: '1px',
  };

  return (
    <div style={containerStyle}>
      {/* HUD */}
      <div style={hudStyle}>
        <div style={hudItemStyle}>
          <div style={hudValueStyle}>{score}</div>
          <div style={hudLabelStyle}>Score</div>
        </div>
        <div style={hudItemStyle}>
          <div style={hudValueStyle}>{timeRemaining}</div>
          <div style={hudLabelStyle}>Time</div>
        </div>
        <div style={hudItemStyle}>
          <div style={hudValueStyle}>{shotsMade}/{shotsTaken}</div>
          <div style={hudLabelStyle}>Goals</div>
        </div>
      </div>

      {/* Game Canvas */}
      <div ref={containerRef} style={{ flex: 1, position: 'relative' }}>
        <canvas
          ref={canvasRef}
          style={{
            width: '100%',
            height: '100%',
            display: 'block',
            touchAction: 'none',
          }}
        />
      </div>

      {/* Instructions */}
      {gameState === 'aiming' && (
        <div style={{
          position: 'absolute',
          bottom: '80px',
          left: '50%',
          transform: 'translateX(-50%)',
          background: 'rgba(0, 0, 0, 0.7)',
          padding: '12px 24px',
          borderRadius: '20px',
          color: '#fff',
          fontSize: '14px',
          fontWeight: 600,
          textAlign: 'center',
          pointerEvents: 'none',
        }}>
          Drag to aim ↑ Hold to power up → Release to shoot!
        </div>
      )}
    </div>
  );
}
