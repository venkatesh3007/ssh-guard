import React, { useState, useEffect, useCallback, useRef } from 'react';
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

interface Target {
  id: number;
  x: number;
  y: number;
  points: number;
  size: number;
  color: string;
}

export default function GameScreen({
  gameConfig,
  timeRemaining,
  isPlaying,
  score,
  shotsTaken,
  shotsMade,
  currentStreak,
  onShot,
  onGameOver,
  setTimeRemaining,
  setIsPlaying,
}: GameScreenProps) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [goalkeeperX, setGoalkeeperX] = useState(50);
  const [goalkeeperDirection, setGoalkeeperDirection] = useState(1);
  const [showResult, setShowResult] = useState<ShotResult | null>(null);
  const [comboMultiplier, setComboMultiplier] = useState(1);
  const gameAreaRef = useRef<HTMLDivElement>(null);
  const targetIdRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Generate random targets
  const generateTarget = useCallback((): Target => {
    const points = Math.floor(Math.random() * 3) + 1; // 1-3 points
    const size = gameConfig.targetSize - (points - 1) * 10;
    const colors = ['#ff6b35', '#f7931e', '#ffd700'];
    
    return {
      id: targetIdRef.current++,
      x: Math.random() * 80 + 10, // 10-90%
      y: Math.random() * 50 + 20, // 20-70%
      points,
      size,
      color: colors[points - 1],
    };
  }, [gameConfig.targetSize]);

  // Initialize targets
  useEffect(() => {
    const initialTargets = Array.from({ length: 3 }, generateTarget);
    setTargets(initialTargets);
  }, [generateTarget]);

  // Timer countdown
  useEffect(() => {
    if (isPlaying && timeRemaining > 0) {
      timerRef.current = setInterval(() => {
        setTimeRemaining(timeRemaining - 1);
      }, 1000);
    } else if (timeRemaining <= 0 && isPlaying) {
      setIsPlaying(false);
      onGameOver(score);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, timeRemaining, setTimeRemaining, setIsPlaying, onGameOver, score]);

  // Goalkeeper movement
  useEffect(() => {
    if (!isPlaying) return;
    
    const interval = setInterval(() => {
      setGoalkeeperX(prev => {
        const newX = prev + goalkeeperDirection * gameConfig.goalkeeperSpeed;
        if (newX >= 85 || newX <= 15) {
          setGoalkeeperDirection(-goalkeeperDirection);
        }
        return Math.max(15, Math.min(85, newX));
      });
    }, 50);

    return () => clearInterval(interval);
  }, [isPlaying, goalkeeperDirection, gameConfig.goalkeeperSpeed]);

  // Spawn new targets periodically
  useEffect(() => {
    if (!isPlaying) return;
    
    const interval = setInterval(() => {
      setTargets(prev => {
        if (prev.length < 5) {
          return [...prev, generateTarget()];
        }
        return prev;
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [isPlaying, generateTarget]);

  const handleTargetClick = (target: Target) => {
    if (!isPlaying) return;

    // Check if goalkeeper is blocking
    const goalkeeperBlocking = Math.abs(goalkeeperX - target.x) < 15;
    
    let result: ShotResult;
    
    if (goalkeeperBlocking) {
      result = {
        made: false,
        points: 0,
        multiplier: 1,
        message: 'SAVED!',
      };
      setComboMultiplier(1);
    } else {
      const newMultiplier = Math.min(comboMultiplier + 0.5, 3);
      setComboMultiplier(newMultiplier);
      
      const points = Math.round(target.points * newMultiplier);
      
      let message = 'GOAL!';
      if (currentStreak >= 2) message = 'HAT TRICK!';
      if (currentStreak >= 4) message = 'UNSTOPPABLE!';
      if (target.points === 3) message = 'PERFECT SHOT!';
      
      result = {
        made: true,
        points,
        multiplier: newMultiplier,
        message,
      };
    }

    onShot(result);
    setShowResult(result);
    
    // Remove clicked target and spawn new one
    setTargets(prev => {
      const filtered = prev.filter(t => t.id !== target.id);
      if (filtered.length < 3) {
        return [...filtered, generateTarget()];
      }
      return filtered;
    });

    // Hide result after delay
    setTimeout(() => setShowResult(null), 1000);
  };

  const containerStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    background: 'linear-gradient(180deg, #87CEEB 0%, #98FB98 60%, #228B22 100%)',
    position: 'relative',
    overflow: 'hidden',
  };

  const hudStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 16px',
    background: 'rgba(0, 0, 0, 0.6)',
    backdropFilter: 'blur(10px)',
    zIndex: 10,
  };

  const hudItemStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
  };

  const hudValueStyle: React.CSSProperties = {
    fontSize: '24px',
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

  const gameAreaStyle: React.CSSProperties = {
    flex: 1,
    position: 'relative',
    cursor: 'crosshair',
  };

  const goalStyle: React.CSSProperties = {
    position: 'absolute',
    top: '10%',
    left: '10%',
    right: '10%',
    height: '40%',
    border: '4px solid #fff',
    borderBottom: 'none',
    borderRadius: '8px 8px 0 0',
    background: 'rgba(255, 255, 255, 0.1)',
  };

  const goalNetStyle: React.CSSProperties = {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundImage: `
      linear-gradient(90deg, rgba(255,255,255,0.3) 1px, transparent 1px),
      linear-gradient(rgba(255,255,255,0.3) 1px, transparent 1px)
    `,
    backgroundSize: '20px 20px',
    opacity: 0.5,
  };

  const goalkeeperStyle: React.CSSProperties = {
    position: 'absolute',
    bottom: '0',
    left: `${goalkeeperX}%`,
    transform: 'translateX(-50%)',
    width: '50px',
    height: '60px',
    background: 'linear-gradient(135deg, #ff4444 0%, #cc0000 100%)',
    borderRadius: '8px 8px 4px 4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '24px',
    transition: 'left 0.1s linear',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
    zIndex: 5,
  };

  const targetStyle = (target: Target): React.CSSProperties => ({
    position: 'absolute',
    left: `${target.x}%`,
    top: `${target.y}%`,
    width: `${target.size}px`,
    height: `${target.size}px`,
    borderRadius: '50%',
    background: `radial-gradient(circle at 30% 30%, ${target.color} 0%, ${target.color}dd 100%)`,
    border: '3px solid #fff',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: `${target.size * 0.4}px`,
    fontWeight: 900,
    color: '#fff',
    cursor: 'pointer',
    transform: 'translate(-50%, -50%)',
    boxShadow: `0 4px 16px ${target.color}66`,
    animation: 'pulse 1s ease-in-out infinite',
    zIndex: 4,
  });

  const resultOverlayStyle: React.CSSProperties = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    fontSize: '48px',
    fontWeight: 900,
    color: showResult?.made ? '#ffd700' : '#ff4444',
    textShadow: '0 4px 12px rgba(0, 0, 0, 0.5)',
    zIndex: 20,
    pointerEvents: 'none',
    animation: 'popIn 0.3s ease-out',
  };

  const streakStyle: React.CSSProperties = {
    position: 'absolute',
    top: '60px',
    right: '16px',
    background: 'rgba(255, 107, 53, 0.9)',
    color: '#fff',
    padding: '8px 16px',
    borderRadius: '20px',
    fontSize: '14px',
    fontWeight: 700,
    zIndex: 10,
    display: currentStreak > 1 ? 'block' : 'none',
  };

  const multiplierStyle: React.CSSProperties = {
    position: 'absolute',
    top: '60px',
    left: '16px',
    background: 'rgba(255, 215, 0, 0.9)',
    color: '#000',
    padding: '8px 16px',
    borderRadius: '20px',
    fontSize: '14px',
    fontWeight: 700,
    zIndex: 10,
    display: comboMultiplier > 1 ? 'block' : 'none',
  };

  const fieldLinesStyle: React.CSSProperties = {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: '50%',
    background: 'linear-gradient(180deg, transparent 0%, rgba(34, 139, 34, 0.3) 100%)',
  };

  return (
    <div style={containerStyle}>
      <style>{`
        @keyframes pulse {
          0%, 100% { transform: translate(-50%, -50%) scale(1); }
          50% { transform: translate(-50%, -50%) scale(1.1); }
        }
        @keyframes popIn {
          0% { transform: translate(-50%, -50%) scale(0); opacity: 0; }
          50% { transform: translate(-50%, -50%) scale(1.2); }
          100% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
        }
      `}</style>

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

      {/* Streak indicator */}
      <div style={streakStyle}>
        🔥 {currentStreak}x Streak!
      </div>

      {/* Multiplier indicator */}
      <div style={multiplierStyle}>
        ⚡ x{comboMultiplier.toFixed(1)}
      </div>

      {/* Game Area */}
      <div style={gameAreaStyle} ref={gameAreaRef}>
        <div style={fieldLinesStyle} />
        
        {/* Goal */}
        <div style={goalStyle}>
          <div style={goalNetStyle} />
        </div>

        {/* Goalkeeper */}
        <div style={goalkeeperStyle}>🧤</div>

        {/* Targets */}
        {targets.map(target => (
          <div
            key={target.id}
            style={targetStyle(target)}
            onClick={() => handleTargetClick(target)}
          >
            {target.points}x
          </div>
        ))}

        {/* Result overlay */}
        {showResult && (
          <div style={resultOverlayStyle}>
            {showResult.message}
            {showResult.made && (
              <div style={{ fontSize: '24px', textAlign: 'center' }}>
                +{showResult.points} pts
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
