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
const GRAVITY = 0.22;
const BALL_RADIUS = 14;
const POWER_MAX = 24;
const POWER_MIN = 5;
const OPTIMAL_POWER_MIN = 10;   // below this = too slow, keeper saves easily
const OPTIMAL_POWER_MAX = 18;   // above this = over the bar

interface Ball {
  x: number; y: number; vx: number; vy: number;
  radius: number; rotation: number;
  active: boolean; scored: boolean; saved: boolean; scale: number;
}

interface Goalkeeper {
  x: number; y: number;
  width: number; height: number;
  vx: number; state: 'idle' | 'ready' | 'diving' | 'celebrating' | 'sad';
  diveTarget: number;
  baseX: number;
  movePhase: number;
  reactionSpeed: number;
  predictAccuracy: number;
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
  const [gameState, setGameState] = useState<'aiming'|'charging'|'shooting'|'result'>('aiming');
  const [message, setMessage] = useState('');
  const [showConfetti, setShowConfetti] = useState(false);
  const [slowMo, setSlowMo] = useState(false);

  const ballRef = useRef<Ball>({
    x:0,y:0,vx:0,vy:0,radius:BALL_RADIUS,rotation:0,active:false,scored:false,saved:false,scale:1,
  });
  const keeperRef = useRef<Goalkeeper>({
    x:0,y:0,width:50,height:70,vx:0,state:'idle',diveTarget:0,baseX:0,movePhase:0,reactionSpeed:1,predictAccuracy:0.7,
  });
  const particlesRef = useRef<Particle[]>([]);
  const animRef = useRef<number>(0);
  const powerRef = useRef(0);
  const aimRef = useRef({ angle: -Math.PI/2 });
  const touchRef = useRef({ startX:0, startY:0, isDragging:false });
  const goalsScoredRef = useRef(0);

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

  const createParticles = useCallback((x:number,y:number,color:string,count:number) => {
    for (let i=0;i<count;i++) particlesRef.current.push({
      x,y,vx:(Math.random()-0.5)*14,vy:(Math.random()-0.5)*14-5,life:1,color,size:Math.random()*5+2,
    });
  }, []);

  const resetPositions = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const w = canvas.width, h = canvas.height;
    ballRef.current = { x:w/2, y:h-90, vx:0, vy:0, radius:BALL_RADIUS, rotation:0, active:false, scored:false, saved:false, scale:1 };
    const kx = w/2;
    keeperRef.current = {
      x:kx, y:150, width:50, height:70, vx:0, state:'idle', diveTarget:kx,
      baseX:kx, movePhase:Math.random()*Math.PI*2, reactionSpeed:1, predictAccuracy:0.7,
    };
    setGameState('aiming');
    powerRef.current = 0;
    setMessage('');
    setShowConfetti(false);
    setSlowMo(false);
    touchRef.current.isDragging = false;
  }, []);

  // ─── Touch / Mouse ──────────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const getPos = (e:MouseEvent|TouchEvent) => {
      const rect = canvas.getBoundingClientRect();
      const cx = 'touches' in e ? (e.touches[0]?.clientX ?? e.changedTouches[0]?.clientX) : e.clientX;
      const cy = 'touches' in e ? (e.touches[0]?.clientY ?? e.changedTouches[0]?.clientY) : e.clientY;
      return { x:(cx||0)-rect.left, y:(cy||0)-rect.top };
    };

    const onStart = (e:MouseEvent|TouchEvent) => {
      if (gameState !== 'aiming') return;
      e.preventDefault();
      const pos = getPos(e);
      touchRef.current = { startX:pos.x, startY:pos.y, isDragging:true };
      setGameState('charging');
    };

    const onMove = (e:MouseEvent|TouchEvent) => {
      if (!touchRef.current.isDragging || gameState !== 'charging') return;
      e.preventDefault();
      const pos = getPos(e);
      const ball = ballRef.current;
      const dx = pos.x - ball.x;
      const dy = pos.y - ball.y;
      aimRef.current.angle = Math.atan2(dy, dx);
      const dist = Math.min(Math.sqrt(dx*dx + dy*dy) / 3, POWER_MAX);
      powerRef.current = Math.max(dist, POWER_MIN);
    };

    const onEnd = (e:MouseEvent|TouchEvent) => {
      if (!touchRef.current.isDragging || gameState !== 'charging') return;
      e.preventDefault();
      touchRef.current.isDragging = false;

      const ball = ballRef.current;
      const pwr = Math.max(powerRef.current, POWER_MIN);
      const angle = aimRef.current.angle;

      if (angle > -0.15) {
        setGameState('aiming'); powerRef.current = 0;
        setMessage('Aim higher!'); setTimeout(()=>setMessage(''), 1000);
        return;
      }

      ball.vx = Math.cos(angle) * pwr;
      ball.vy = Math.sin(angle) * pwr;
      ball.active = true;

      // Keeper AI
      const keeper = keeperRef.current;
      const canvas = canvasRef.current;
      if (canvas) {
        const w = canvas.width;
        const goalW = w * 0.7;
        const goalLeft = (w - goalW)/2;
        const goalRight = (w + goalW)/2;
        const timeToKeeper = (keeper.y - ball.y) / ball.vy;
        let predictedX = ball.x + ball.vx * timeToKeeper;

        // Keeper prediction accuracy increases with goals scored (harder over time)
        const accuracy = keeper.predictAccuracy + goalsScoredRef.current * 0.05;
        if (Math.random() > accuracy) {
          predictedX += (Math.random()-0.5) * 150; // wrong prediction
        }
        predictedX = Math.max(goalLeft+25, Math.min(goalRight-25, predictedX));
        keeper.diveTarget = predictedX;
        keeper.state = 'diving';
        keeper.vx = (predictedX - keeper.x) / (12 / keeper.reactionSpeed);
      }

      setGameState('shooting');
      powerRef.current = 0;
    };

    canvas.addEventListener('mousedown', onStart);
    canvas.addEventListener('mousemove', onMove);
    canvas.addEventListener('mouseup', onEnd);
    canvas.addEventListener('touchstart', onStart, { passive:false });
    canvas.addEventListener('touchmove', onMove, { passive:false });
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

  // ─── Game Loop ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let frameCount = 0;

    const drawField = (w:number, h:number) => {
      // Sky
      const sky = ctx.createLinearGradient(0,0,0,h*0.45);
      sky.addColorStop(0,'#0a1f35'); sky.addColorStop(1,'#1d4a6e');
      ctx.fillStyle = sky; ctx.fillRect(0,0,w,h*0.45);

      // Stands
      ctx.fillStyle = '#060d1a'; ctx.fillRect(0,35,w,55);
      for (let i=0;i<w;i+=5) {
        for (let j=40;j<80;j+=6) {
          ctx.fillStyle = `hsl(${200+Math.random()*50},55%,${25+Math.random()*30}%)`;
          ctx.fillRect(i,j,3,4);
        }
      }

      // Field
      const fieldTop = 120;
      const goalW = w*0.7;
      const grass = ctx.createLinearGradient(0,fieldTop,0,h);
      grass.addColorStop(0,'#2a5c2e'); grass.addColorStop(1,'#3d8b42');
      ctx.fillStyle = grass;
      ctx.beginPath();
      ctx.moveTo((w-goalW)/2, fieldTop);
      ctx.lineTo((w+goalW)/2, fieldTop);
      ctx.lineTo(w, h);
      ctx.lineTo(0, h);
      ctx.closePath(); ctx.fill();

      // Stripes
      ctx.save();
      ctx.beginPath();
      ctx.moveTo((w-goalW)/2, fieldTop); ctx.lineTo((w+goalW)/2, fieldTop);
      ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath(); ctx.clip();
      for (let i=-w;i<w*2;i+=35) {
        ctx.fillStyle = 'rgba(255,255,255,0.03)';
        ctx.fillRect(i, fieldTop, 17, h-fieldTop);
      }
      ctx.restore();

      // Goal line
      ctx.strokeStyle = 'rgba(255,255,255,0.85)';
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.moveTo((w-goalW)/2, fieldTop); ctx.lineTo((w+goalW)/2, fieldTop); ctx.stroke();

      // Penalty box
      const boxW = goalW*0.55;
      ctx.strokeStyle = 'rgba(255,255,255,0.5)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo((w-boxW)/2, fieldTop+70);
      ctx.lineTo((w-boxW)/2, fieldTop);
      ctx.lineTo((w+boxW)/2, fieldTop);
      ctx.lineTo((w+boxW)/2, fieldTop+70);
      ctx.stroke();

      // Penalty spot
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(w/2, fieldTop+70+35, 3, 0, Math.PI*2); ctx.fill();

      // Goal posts
      const postH = 75;
      ctx.strokeStyle = '#fff'; ctx.lineWidth = 5;
      ctx.beginPath();
      ctx.moveTo((w-goalW)/2, fieldTop); ctx.lineTo((w-goalW)/2, fieldTop-postH);
      ctx.lineTo((w+goalW)/2, fieldTop-postH); ctx.lineTo((w+goalW)/2, fieldTop);
      ctx.stroke();

      // Net
      ctx.strokeStyle = 'rgba(255,255,255,0.2)'; ctx.lineWidth = 1;
      for (let x=(w-goalW)/2; x<=(w+goalW)/2; x+=10) {
        ctx.beginPath(); ctx.moveTo(x, fieldTop-postH); ctx.lineTo(x, fieldTop); ctx.stroke();
      }
      for (let y=fieldTop-postH; y<=fieldTop; y+=10) {
        ctx.beginPath(); ctx.moveTo((w-goalW)/2, y); ctx.lineTo((w+goalW)/2, y); ctx.stroke();
      }

      // StuCred banner
      ctx.fillStyle = 'rgba(255,107,53,0.25)';
      ctx.fillRect((w-goalW)/2+15, fieldTop-postH-22, goalW-30, 18);
      ctx.fillStyle = '#f7931e'; ctx.font = 'bold 11px Montserrat';
      ctx.textAlign = 'center'; ctx.fillText('STUCRED', w/2, fieldTop-postH-9);
    };

    const loop = () => {
      const w = canvas.width, h = canvas.height;
      const centerX = w/2;
      const goalW = w*0.7;
      const goalLeft = (w-goalW)/2;
      const goalRight = (w+goalW)/2;
      const fieldTop = 120;
      const timeScale = slowMo ? 0.3 : 1;
      frameCount++;

      ctx.clearRect(0,0,w,h);
      drawField(w,h);

      const ball = ballRef.current;
      const keeper = keeperRef.current;

      // ── Keeper idle movement ──
      if (keeper.state === 'idle' || keeper.state === 'ready') {
        keeper.movePhase += 0.04;
        const sway = Math.sin(keeper.movePhase) * 40;
        keeper.x = keeper.baseX + sway;
        keeper.state = 'ready';

        // Keeper bounces on toes
        keeper.y = 150 + Math.sin(keeper.movePhase*2) * 3;
      }

      // ── Ball physics ──
      if (ball.active) {
        ball.x += ball.vx * timeScale;
        ball.y += ball.vy * timeScale;
        ball.vy += GRAVITY * timeScale;
        ball.rotation += ball.vx * 0.08 * timeScale;
        ball.scale = Math.max(0.45, 1 - (fieldTop - ball.y)/500);

        // Wind effect (subtle curve)
        ball.vx += Math.sin(frameCount * 0.02) * 0.03 * timeScale;

        // ── Power check ──
        const powerUsed = Math.sqrt(ball.vx*ball.vx + ball.vy*ball.vy);

        // Too weak = slow shot, easy save
        if (powerUsed < OPTIMAL_POWER_MIN && ball.y < fieldTop + 50 && !ball.scored && !ball.saved) {
          ball.saved = true; ball.active = false;
          keeper.state = 'celebrating';
          setGameState('result');
          setMessage('Too weak!');
          createParticles(ball.x, ball.y, '#888', 10);
          onShot({ made:false, points:0, multiplier:1, message:'Too weak!' });
          setTimeout(resetPositions, 1800);
        }

        // Too strong = over the bar
        if (powerUsed > OPTIMAL_POWER_MAX && ball.y < fieldTop - 30 && !ball.scored && !ball.saved) {
          if (ball.y < fieldTop - 60) {
            ball.active = false;
            setGameState('result');
            setMessage('Over the bar!');
            createParticles(ball.x, fieldTop, '#fff', 8);
            onShot({ made:false, points:0, multiplier:1, message:'Over the bar!' });
            setTimeout(resetPositions, 1800);
          }
        }

        // ── Goal check ──
        if (ball.y < fieldTop && ball.y > fieldTop-20 &&
            ball.x > goalLeft+5 && ball.x < goalRight-5 &&
            !ball.scored && !ball.saved) {
          ball.scored = true; ball.active = false;
          keeper.state = 'sad';
          goalsScoredRef.current++;
          setGameState('result');
          setMessage('GOAL!!!');
          setShowConfetti(true);
          setSlowMo(true);
          setTimeout(()=>setSlowMo(false), 800);
          createParticles(ball.x, ball.y, '#ffd700', 50);
          onShot({ made:true, points:100, multiplier:1, message:'GOAL!' });
          setTimeout(resetPositions, 2500);
        }

        // ── Miss check ──
        if ((ball.y < fieldTop-80 || ball.x < -60 || ball.x > w+60 || ball.y > h+60) &&
            !ball.scored && !ball.saved) {
          ball.active = false;
          setGameState('result');
          setMessage(ball.y < fieldTop-80 ? 'Over the bar!' : 'Wide!');
          onShot({ made:false, points:0, multiplier:1, message:'Missed!' });
          setTimeout(resetPositions, 1800);
        }
      }

      // ── Keeper diving ──
      if (keeper.state === 'diving') {
        keeper.x += keeper.vx * timeScale;
        keeper.y = 150 - Math.abs(keeper.x - centerX) * 0.2;

        // Collision
        if (ball.active && !ball.saved && !ball.scored) {
          const dx = ball.x - keeper.x;
          const dy = ball.y - (keeper.y - keeper.height/2);
          const dist = Math.sqrt(dx*dx + dy*dy);
          if (dist < ball.radius + keeper.width*0.55) {
            ball.saved = true; ball.active = false;
            keeper.state = 'celebrating';
            setGameState('result');
            setMessage('SAVED!');
            createParticles(ball.x, ball.y, '#ff4444', 25);
            onShot({ made:false, points:0, multiplier:1, message:'Saved!' });
            setTimeout(resetPositions, 1800);
          }
        }

        if (Math.abs(keeper.x - keeper.diveTarget) < 4) keeper.vx *= 0.85;
      }

      // ── Draw keeper ──
      ctx.save();
      ctx.translate(keeper.x, keeper.y);
      const kScale = 0.75 + (keeper.y-100)/350;
      ctx.scale(kScale, kScale);

      // Body
      const kg = ctx.createLinearGradient(0,-keeper.height,0,0);
      kg.addColorStop(0, keeper.state==='sad' ? '#cc4422' : '#ff6b35');
      kg.addColorStop(1, keeper.state==='sad' ? '#aa3311' : '#f7931e');
      ctx.fillStyle = kg;
      ctx.fillRect(-keeper.width/2, -keeper.height, keeper.width, keeper.height);

      // Head
      ctx.fillStyle = '#fdbf60';
      ctx.beginPath(); ctx.arc(0, -keeper.height-14, 15, 0, Math.PI*2); ctx.fill();

      // Eyes (follow ball)
      const eyeDir = ball.active ? Math.atan2(ball.y-keeper.y, ball.x-keeper.x) : 0;
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(-6, -keeper.height-16, 5, 0, Math.PI*2); ctx.fill();
      ctx.beginPath(); ctx.arc(6, -keeper.height-16, 5, 0, Math.PI*2); ctx.fill();
      ctx.fillStyle = '#222';
      ctx.beginPath(); ctx.arc(-6+Math.cos(eyeDir)*2, -keeper.height-16+Math.sin(eyeDir)*2, 2.5, 0, Math.PI*2); ctx.fill();
      ctx.beginPath(); ctx.arc(6+Math.cos(eyeDir)*2, -keeper.height-16+Math.sin(eyeDir)*2, 2.5, 0, Math.PI*2); ctx.fill();

      // Gloves
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(-keeper.width/2-10, -keeper.height/2, 11, 0, Math.PI*2); ctx.fill();
      ctx.beginPath(); ctx.arc(keeper.width/2+10, -keeper.height/2, 11, 0, Math.PI*2); ctx.fill();

      ctx.restore();

      // ── Draw ball ──
      ctx.save();
      ctx.translate(ball.x, ball.y);
      ctx.scale(ball.scale, ball.scale);
      ctx.rotate(ball.rotation);

      ctx.fillStyle = 'rgba(0,0,0,0.3)';
      ctx.beginPath();
      ctx.ellipse(0, ball.radius+5, ball.radius*0.7, ball.radius*0.25, 0, 0, Math.PI*2); ctx.fill();

      const bg = ctx.createRadialGradient(-4,-4,0,0,0,ball.radius);
      bg.addColorStop(0,'#fff'); bg.addColorStop(0.6,'#e8e8e8'); bg.addColorStop(1,'#999');
      ctx.fillStyle = bg;
      ctx.beginPath(); ctx.arc(0,0,ball.radius,0,Math.PI*2); ctx.fill();

      ctx.strokeStyle = '#222'; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(0,0,ball.radius*0.55,0,Math.PI*2); ctx.stroke();
      for (let i=0;i<5;i++) {
        const a = (i/5)*Math.PI*2;
        ctx.beginPath(); ctx.moveTo(0,0); ctx.lineTo(Math.cos(a)*ball.radius*0.55, Math.sin(a)*ball.radius*0.55); ctx.stroke();
      }
      ctx.restore();

      // ── Aim guide ──
      if (gameState === 'charging') {
        const angle = aimRef.current.angle;
        const pwr = powerRef.current;

        // Trajectory preview
        ctx.strokeStyle = `rgba(255,255,255,${0.15 + (pwr/POWER_MAX)*0.35})`;
        ctx.lineWidth = 2; ctx.setLineDash([5,5]);
        ctx.beginPath(); ctx.moveTo(ball.x, ball.y);
        let sx=ball.x, sy=ball.y, svx=Math.cos(angle)*pwr, svy=Math.sin(angle)*pwr;
        for (let i=0;i<35;i++) {
          sx+=svx; sy+=svy; svy+=GRAVITY;
          ctx.lineTo(sx,sy); if (sy<fieldTop) break;
        }
        ctx.stroke(); ctx.setLineDash([]);

        // Target dot
        ctx.fillStyle = `rgba(255,255,255,${0.3 + (pwr/POWER_MAX)*0.4})`;
        ctx.beginPath(); ctx.arc(sx, sy, 4, 0, Math.PI*2); ctx.fill();

        // Power bar
        const barW = 140, barH = 14, barX = centerX-barW/2, barY = h-55;
        ctx.fillStyle = 'rgba(0,0,0,0.6)'; ctx.fillRect(barX, barY, barW, barH);

        const pct = Math.min(pwr/POWER_MAX, 1);
        // Color zones: green (optimal), yellow, red
        let col = '#00ff88';
        if (pwr < OPTIMAL_POWER_MIN) col = '#ffaa00'; // too weak
        else if (pwr > OPTIMAL_POWER_MAX) col = '#ff4444'; // too strong
        else col = '#00ff88'; // sweet spot

        ctx.fillStyle = col;
        ctx.fillRect(barX, barY, barW*pct, barH);

        // Optimal zone markers
        const optMinX = barX + barW * (OPTIMAL_POWER_MIN/POWER_MAX);
        const optMaxX = barX + barW * (OPTIMAL_POWER_MAX/POWER_MAX);
        ctx.strokeStyle = '#fff'; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(optMinX, barY-3); ctx.lineTo(optMinX, barY+barH+3); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(optMaxX, barY-3); ctx.lineTo(optMaxX, barY+barH+3); ctx.stroke();

        ctx.strokeStyle = '#fff'; ctx.lineWidth = 1; ctx.strokeRect(barX, barY, barW, barH);

        ctx.fillStyle = '#fff'; ctx.font = 'bold 11px Montserrat'; ctx.textAlign = 'center';
        ctx.fillText('SWEET SPOT', centerX, barY-8);
      }

      // ── Particles ──
      particlesRef.current = particlesRef.current.filter(p => {
        p.x += p.vx; p.y += p.vy; p.vy += 0.15; p.life -= 0.025;
        if (p.life > 0) {
          ctx.globalAlpha = p.life; ctx.fillStyle = p.color;
          ctx.beginPath(); ctx.arc(p.x, p.y, p.size*p.life, 0, Math.PI*2); ctx.fill();
          ctx.globalAlpha = 1; return true;
        }
        return false;
      });

      // ── Message ──
      if (message) {
        ctx.fillStyle = message.includes('GOAL') ? '#ffd700' : message.includes('SAVED')||message.includes('weak') ? '#ff6666' : '#fff';
        ctx.font = 'bold 38px Montserrat'; ctx.textAlign = 'center';
        ctx.shadowColor = 'rgba(0,0,0,0.9)'; ctx.shadowBlur = 12;
        ctx.fillText(message, centerX, h/2);
        ctx.shadowBlur = 0;
      }

      // ── Confetti ──
      if (showConfetti) {
        for (let i=0;i<80;i++) {
          const x = Math.random()*w, y = Math.random()*h*0.6;
          const sz = Math.random()*6+2;
          ctx.fillStyle = `hsl(${Math.random()*360},100%,60%)`;
          ctx.fillRect(x,y,sz,sz);
        }
      }

      // ── Instructions ──
      if (gameState === 'aiming') {
        ctx.fillStyle = 'rgba(255,255,255,0.7)'; ctx.font = '13px Montserrat'; ctx.textAlign = 'center';
        ctx.fillText('Pull back from ball to aim. Stay in the GREEN zone for power!', centerX, h-22);
      }

      animRef.current = requestAnimationFrame(loop);
    };

    animRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animRef.current);
  }, [gameState, message, showConfetti, slowMo, createParticles, resetPositions, onShot]);

  return (
    <div style={{ width:'100%', height:'100%', display:'flex', flexDirection:'column', background:'#0a1628', position:'relative', overflow:'hidden' }}>
      {/* HUD */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'10px 20px', background:'rgba(0,0,0,0.85)', zIndex:10 }}>
        <div style={{textAlign:'center'}}>
          <div style={{fontSize:'22px', fontWeight:900, color:'#f7931e'}}>{score}</div>
          <div style={{fontSize:'10px', color:'rgba(255,255,255,0.6)', textTransform:'uppercase'}}>Score</div>
        </div>
        <div style={{textAlign:'center'}}>
          <div style={{fontSize:'22px', fontWeight:900, color:'#f7931e'}}>{timeRemaining}</div>
          <div style={{fontSize:'10px', color:'rgba(255,255,255,0.6)', textTransform:'uppercase'}}>Time</div>
        </div>
        <div style={{textAlign:'center'}}>
          <div style={{fontSize:'22px', fontWeight:900, color:'#f7931e'}}>{shotsMade}/{shotsTaken}</div>
          <div style={{fontSize:'10px', color:'rgba(255,255,255,0.6)', textTransform:'uppercase'}}>Goals</div>
        </div>
      </div>

      {/* Canvas */}
      <div ref={containerRef} style={{flex:1, position:'relative'}}>
        <canvas ref={canvasRef} style={{width:'100%', height:'100%', display:'block', touchAction:'none'}} />
      </div>
    </div>
  );
}
