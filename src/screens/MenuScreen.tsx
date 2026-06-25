import React from 'react';

interface MenuScreenProps {
  highScore: number;
  totalGames: number;
  onStartGame: () => void;
  onShowLeaderboard: () => void;
}

export default function MenuScreen({ highScore, totalGames, onStartGame, onShowLeaderboard }: MenuScreenProps) {
  const containerStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'linear-gradient(135deg, #0a1628 0%, #1a3a5c 50%, #0a1628 100%)',
    position: 'relative',
    overflow: 'hidden',
  };

  const logoContainerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    marginBottom: '40px',
    zIndex: 2,
  };

  const logoStyle: React.CSSProperties = {
    width: '120px',
    height: '120px',
    borderRadius: '50%',
    background: 'linear-gradient(135deg, #ff6b35 0%, #f7931e 100%)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '48px',
    fontWeight: 900,
    color: '#fff',
    marginBottom: '16px',
    boxShadow: '0 8px 32px rgba(255, 107, 53, 0.4)',
    border: '4px solid rgba(255, 255, 255, 0.2)',
  };

  const titleStyle: React.CSSProperties = {
    fontSize: '32px',
    fontWeight: 900,
    color: '#fff',
    textAlign: 'center',
    textShadow: '0 4px 12px rgba(0, 0, 0, 0.5)',
    letterSpacing: '2px',
  };

  const subtitleStyle: React.CSSProperties = {
    fontSize: '16px',
    fontWeight: 600,
    color: '#f7931e',
    marginTop: '8px',
    letterSpacing: '4px',
    textTransform: 'uppercase',
  };

  const statsContainerStyle: React.CSSProperties = {
    display: 'flex',
    gap: '24px',
    marginBottom: '40px',
    zIndex: 2,
  };

  const statBoxStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.1)',
    backdropFilter: 'blur(10px)',
    borderRadius: '16px',
    padding: '16px 24px',
    textAlign: 'center',
    border: '1px solid rgba(255, 255, 255, 0.2)',
    minWidth: '120px',
  };

  const statValueStyle: React.CSSProperties = {
    fontSize: '28px',
    fontWeight: 900,
    color: '#f7931e',
  };

  const statLabelStyle: React.CSSProperties = {
    fontSize: '12px',
    fontWeight: 600,
    color: 'rgba(255, 255, 255, 0.7)',
    marginTop: '4px',
    textTransform: 'uppercase',
    letterSpacing: '1px',
  };

  const buttonStyle: React.CSSProperties = {
    width: '280px',
    padding: '18px 32px',
    borderRadius: '50px',
    border: 'none',
    fontSize: '20px',
    fontWeight: 700,
    fontFamily: 'Montserrat, sans-serif',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    textTransform: 'uppercase',
    letterSpacing: '2px',
    zIndex: 2,
  };

  const primaryButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: 'linear-gradient(135deg, #ff6b35 0%, #f7931e 100%)',
    color: '#fff',
    marginBottom: '16px',
    boxShadow: '0 8px 32px rgba(255, 107, 53, 0.4)',
  };

  const secondaryButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: 'rgba(255, 255, 255, 0.1)',
    color: '#fff',
    border: '2px solid rgba(255, 255, 255, 0.3)',
  };

  const fieldPatternStyle: React.CSSProperties = {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: '40%',
    background: 'linear-gradient(180deg, transparent 0%, rgba(34, 139, 34, 0.3) 100%)',
    zIndex: 1,
  };

  const ballStyle: React.CSSProperties = {
    position: 'absolute',
    width: '60px',
    height: '60px',
    borderRadius: '50%',
    background: 'radial-gradient(circle at 30% 30%, #fff 0%, #ddd 50%, #999 100%)',
    boxShadow: '0 4px 16px rgba(0, 0, 0, 0.3)',
    zIndex: 1,
    animation: 'float 3s ease-in-out infinite',
  };

  return (
    <div style={containerStyle}>
      <style>{`
        @keyframes float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-20px) rotate(180deg); }
        }
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.05); }
        }
      `}</style>

      <div style={fieldPatternStyle} />
      
      {/* Decorative balls */}
      <div style={{ ...ballStyle, top: '10%', left: '10%', animationDelay: '0s' }} />
      <div style={{ ...ballStyle, top: '20%', right: '15%', width: '40px', height: '40px', animationDelay: '1s' }} />
      <div style={{ ...ballStyle, bottom: '30%', left: '20%', width: '30px', height: '30px', animationDelay: '2s' }} />

      <div style={logoContainerStyle}>
        <div style={logoStyle}>S</div>
        <div style={titleStyle}>StuCred</div>
        <div style={subtitleStyle}>Football Challenge</div>
      </div>

      <div style={statsContainerStyle}>
        <div style={statBoxStyle}>
          <div style={statValueStyle}>{highScore}</div>
          <div style={statLabelStyle}>Best Score</div>
        </div>
        <div style={statBoxStyle}>
          <div style={statValueStyle}>{totalGames}</div>
          <div style={statLabelStyle}>Games Played</div>
        </div>
      </div>

      <button
        style={primaryButtonStyle}
        onClick={onStartGame}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.05)';
          e.currentTarget.style.boxShadow = '0 12px 40px rgba(255, 107, 53, 0.6)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.boxShadow = '0 8px 32px rgba(255, 107, 53, 0.4)';
        }}
      >
        Play Now
      </button>

      <button
        style={secondaryButtonStyle}
        onClick={onShowLeaderboard}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = 'rgba(255, 255, 255, 0.2)';
          e.currentTarget.style.transform = 'scale(1.05)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = 'rgba(255, 255, 255, 0.1)';
          e.currentTarget.style.transform = 'scale(1)';
        }}
      >
        Leaderboard
      </button>
    </div>
  );
}
