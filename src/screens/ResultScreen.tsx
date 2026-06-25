import React from 'react';

interface ResultScreenProps {
  score: number;
  highScore: number;
  shotsTaken: number;
  shotsMade: number;
  bestStreak: number;
  onPlayAgain: () => void;
  onBackToMenu: () => void;
  onShowLeaderboard: () => void;
}

export default function ResultScreen({
  score,
  highScore,
  shotsTaken,
  shotsMade,
  bestStreak,
  onPlayAgain,
  onBackToMenu,
  onShowLeaderboard,
}: ResultScreenProps) {
  const accuracy = shotsTaken > 0 ? Math.round((shotsMade / shotsTaken) * 100) : 0;
  const isNewHighScore = score >= highScore && score > 0;
  const isTopThree = score >= 300;

  const containerStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'linear-gradient(135deg, #0a1628 0%, #1a3a5c 50%, #0a1628 100%)',
    padding: '20px',
  };

  const resultCardStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.1)',
    backdropFilter: 'blur(10px)',
    borderRadius: '24px',
    padding: '32px',
    width: '100%',
    maxWidth: '400px',
    border: '1px solid rgba(255, 255, 255, 0.2)',
    textAlign: 'center',
  };

  const titleStyle: React.CSSProperties = {
    fontSize: '28px',
    fontWeight: 900,
    color: '#fff',
    marginBottom: '8px',
  };

  const scoreStyle: React.CSSProperties = {
    fontSize: '64px',
    fontWeight: 900,
    color: '#f7931e',
    marginBottom: '8px',
    textShadow: '0 4px 12px rgba(247, 147, 30, 0.4)',
  };

  const highScoreStyle: React.CSSProperties = {
    fontSize: '16px',
    fontWeight: 600,
    color: 'rgba(255, 255, 255, 0.7)',
    marginBottom: '24px',
  };

  const statsGridStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '12px',
    marginBottom: '24px',
  };

  const statBoxStyle: React.CSSProperties = {
    background: 'rgba(0, 0, 0, 0.3)',
    borderRadius: '12px',
    padding: '12px',
  };

  const statValueStyle: React.CSSProperties = {
    fontSize: '24px',
    fontWeight: 900,
    color: '#f7931e',
  };

  const statLabelStyle: React.CSSProperties = {
    fontSize: '11px',
    fontWeight: 600,
    color: 'rgba(255, 255, 255, 0.6)',
    textTransform: 'uppercase',
    letterSpacing: '1px',
    marginTop: '4px',
  };

  const buttonStyle: React.CSSProperties = {
    width: '100%',
    padding: '16px',
    borderRadius: '50px',
    border: 'none',
    fontSize: '16px',
    fontWeight: 700,
    fontFamily: 'Montserrat, sans-serif',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    textTransform: 'uppercase',
    letterSpacing: '2px',
    marginBottom: '12px',
  };

  const primaryButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: 'linear-gradient(135deg, #ff6b35 0%, #f7931e 100%)',
    color: '#fff',
    boxShadow: '0 8px 32px rgba(255, 107, 53, 0.4)',
  };

  const secondaryButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: 'rgba(255, 255, 255, 0.1)',
    color: '#fff',
    border: '2px solid rgba(255, 255, 255, 0.3)',
  };

  const badgeStyle: React.CSSProperties = {
    display: 'inline-block',
    padding: '8px 16px',
    borderRadius: '20px',
    fontSize: '14px',
    fontWeight: 700,
    marginBottom: '16px',
  };

  const newHighScoreBadgeStyle: React.CSSProperties = {
    ...badgeStyle,
    background: 'linear-gradient(135deg, #ffd700 0%, #ff6b35 100%)',
    color: '#000',
    animation: 'pulse 1s ease-in-out infinite',
  };

  const topThreeBadgeStyle: React.CSSProperties = {
    ...badgeStyle,
    background: 'linear-gradient(135deg, #c0c0c0 0%, #ffd700 100%)',
    color: '#000',
  };

  return (
    <div style={containerStyle}>
      <style>{`
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.05); }
        }
      `}</style>

      <div style={resultCardStyle}>
        {isNewHighScore && (
          <div style={newHighScoreBadgeStyle}>🏆 NEW HIGH SCORE!</div>
        )}
        {!isNewHighScore && isTopThree && (
          <div style={topThreeBadgeStyle}>🥉 TOP 3 WORTHY!</div>
        )}

        <div style={titleStyle}>Match Over!</div>
        <div style={scoreStyle}>{score}</div>
        <div style={highScoreStyle}>
          {isNewHighScore ? 'Personal Best!' : `Best: ${highScore}`}
        </div>

        <div style={statsGridStyle}>
          <div style={statBoxStyle}>
            <div style={statValueStyle}>{shotsMade}/{shotsTaken}</div>
            <div style={statLabelStyle}>Goals</div>
          </div>
          <div style={statBoxStyle}>
            <div style={statValueStyle}>{accuracy}%</div>
            <div style={statLabelStyle}>Accuracy</div>
          </div>
          <div style={statBoxStyle}>
            <div style={statValueStyle}>{bestStreak}</div>
            <div style={statLabelStyle}>Best Streak</div>
          </div>
          <div style={statBoxStyle}>
            <div style={statValueStyle}>{Math.round(score / (shotsTaken || 1))}</div>
            <div style={statLabelStyle}>Avg/Shot</div>
          </div>
        </div>

        <button
          style={primaryButtonStyle}
          onClick={onPlayAgain}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'scale(1.02)';
            e.currentTarget.style.boxShadow = '0 12px 40px rgba(255, 107, 53, 0.6)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'scale(1)';
            e.currentTarget.style.boxShadow = '0 8px 32px rgba(255, 107, 53, 0.4)';
          }}
        >
          Play Again
        </button>

        <button
          style={secondaryButtonStyle}
          onClick={onShowLeaderboard}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.2)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.1)';
          }}
        >
          Leaderboard
        </button>

        <button
          style={{
            ...secondaryButtonStyle,
            border: 'none',
            background: 'transparent',
            color: 'rgba(255, 255, 255, 0.5)',
          }}
          onClick={onBackToMenu}
        >
          Main Menu
        </button>
      </div>
    </div>
  );
}
