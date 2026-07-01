import React, { useState } from 'react';

interface MenuScreenProps {
  highScore: number;
  totalGames: number;
  onStartGame: () => void;
  onShowLeaderboard: () => void;
}

// Football icon component
const FootballIcon = ({ size = 40 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 100 100">
    <defs>
      <radialGradient id="ballGrad" cx="30%" cy="30%">
        <stop offset="0%" stopColor="#fff" />
        <stop offset="50%" stopColor="#f0f0f0" />
        <stop offset="100%" stopColor="#999" />
      </radialGradient>
    </defs>
    <circle cx="50" cy="50" r="48" fill="url(#ballGrad)" stroke="#666" strokeWidth="1" />
    {/* Pentagon center */}
    <polygon points="50,25 73,38 64,62 36,62 27,38" fill="#1a1a1a" stroke="#333" strokeWidth="1" />
    {/* Surrounding pentagons */}
    <polygon points="50,5 60,15 55,22 45,22 40,15" fill="#1a1a1a" stroke="#333" strokeWidth="0.8" />
    <polygon points="75,20 85,28 78,38 68,35 65,25" fill="#1a1a1a" stroke="#333" strokeWidth="0.8" />
    <polygon points="80,55 85,65 75,72 68,65 72,55" fill="#1a1a1a" stroke="#333" strokeWidth="0.8" />
    <polygon points="55,78 62,88 50,95 38,88 45,78" fill="#1a1a1a" stroke="#333" strokeWidth="0.8" />
    <polygon points="20,55 28,65 25,72 15,65 18,55" fill="#1a1a1a" stroke="#333" strokeWidth="0.8" />
    {/* Highlight */}
    <ellipse cx="35" cy="35" rx="12" ry="8" fill="rgba(255,255,255,0.3)" transform="rotate(-30 35 35)" />
  </svg>
);

// Trophy icon
const TrophyIcon = ({ size = 24 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6" />
    <path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18" />
    <path d="M4 22h16" />
    <path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22" />
    <path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22" />
    <path d="M18 2H6v7a6 6 0 0 0 12 0V2Z" />
  </svg>
);

// Games played icon
const GamesIcon = ({ size = 24 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" />
    <path d="M12 6v6l4 2" />
  </svg>
);

export default function MenuScreen({ highScore, totalGames, onStartGame, onShowLeaderboard }: MenuScreenProps) {
  const [showReferral, setShowReferral] = useState(false);

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
    marginBottom: '30px',
    zIndex: 2,
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
    gap: '20px',
    marginBottom: '32px',
    zIndex: 2,
  };

  const statBoxStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.08)',
    backdropFilter: 'blur(10px)',
    borderRadius: '20px',
    padding: '20px 24px',
    textAlign: 'center',
    border: '1px solid rgba(255, 255, 255, 0.15)',
    minWidth: '140px',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '8px',
  };

  const statValueStyle: React.CSSProperties = {
    fontSize: '32px',
    fontWeight: 900,
    color: '#f7931e',
  };

  const statLabelStyle: React.CSSProperties = {
    fontSize: '11px',
    fontWeight: 600,
    color: 'rgba(255, 255, 255, 0.7)',
    textTransform: 'uppercase',
    letterSpacing: '1px',
  };

  const buttonStyle: React.CSSProperties = {
    width: '280px',
    padding: '18px 32px',
    borderRadius: '50px',
    border: 'none',
    fontSize: '18px',
    fontWeight: 700,
    fontFamily: 'Montserrat, sans-serif',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    textTransform: 'uppercase',
    letterSpacing: '2px',
    zIndex: 2,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
  };

  const primaryButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: 'linear-gradient(135deg, #ff6b35 0%, #f7931e 100%)',
    color: '#fff',
    marginBottom: '12px',
    boxShadow: '0 8px 32px rgba(255, 107, 53, 0.4)',
  };

  const secondaryButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: 'rgba(255, 255, 255, 0.1)',
    color: '#fff',
    border: '2px solid rgba(255, 255, 255, 0.3)',
    marginBottom: '12px',
  };

  const referButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: 'linear-gradient(135deg, #00c853 0%, #64dd17 100%)',
    color: '#fff',
    marginBottom: '12px',
    boxShadow: '0 8px 32px rgba(0, 200, 83, 0.3)',
  };

  const fieldPatternStyle: React.CSSProperties = {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: '40%',
    background: 'linear-gradient(180deg, transparent 0%, rgba(34, 139, 34, 0.2) 100%)',
    zIndex: 1,
  };

  // Referral modal styles
  const modalOverlayStyle: React.CSSProperties = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.8)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 100,
  };

  const modalContentStyle: React.CSSProperties = {
    background: 'linear-gradient(135deg, #1a3a5c 0%, #0a1628 100%)',
    borderRadius: '24px',
    padding: '32px',
    maxWidth: '360px',
    width: '90%',
    border: '1px solid rgba(255,255,255,0.2)',
    textAlign: 'center',
  };

  const handleReferralShare = () => {
    const referralLink = `https://stucred.com/football?ref=${Math.random().toString(36).substring(7)}`;
    const shareText = `🏆 Join me in StuCred Football Challenge!\n\nDownload the app → Play the game → Unlock amazing rewards!\n\n${referralLink}`;
    
    if (navigator.share) {
      navigator.share({
        title: 'StuCred Football Challenge',
        text: shareText,
        url: referralLink,
      }).catch(() => {});
    } else {
      navigator.clipboard.writeText(shareText).then(() => {
        alert('Referral link copied to clipboard!');
      }).catch(() => {});
    }
  };

  return (
    <div style={containerStyle}>
      <style>{`
        @keyframes float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50% { transform: translateY(-15px) rotate(5deg); }
        }
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.05); }
        }
        @keyframes bounce {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-10px); }
        }
      `}</style>

      <div style={fieldPatternStyle} />
      
      {/* Decorative footballs */}
      <div style={{ position: 'absolute', top: '8%', left: '8%', animation: 'float 4s ease-in-out infinite', opacity: 0.6 }}>
        <FootballIcon size={50} />
      </div>
      <div style={{ position: 'absolute', top: '15%', right: '10%', animation: 'float 3.5s ease-in-out infinite 0.5s', opacity: 0.4 }}>
        <FootballIcon size={35} />
      </div>
      <div style={{ position: 'absolute', bottom: '25%', left: '15%', animation: 'float 5s ease-in-out infinite 1s', opacity: 0.3 }}>
        <FootballIcon size={28} />
      </div>

      <div style={logoContainerStyle}>
        <div style={{ animation: 'bounce 2s ease-in-out infinite' }}>
          <FootballIcon size={100} />
        </div>
        <div style={titleStyle}>StuCred</div>
        <div style={subtitleStyle}>Football Challenge</div>
      </div>

      <div style={statsContainerStyle}>
        <div style={statBoxStyle}>
          <TrophyIcon size={28} />
          <div style={statValueStyle}>{highScore}</div>
          <div style={statLabelStyle}>Best Score</div>
        </div>
        <div style={statBoxStyle}>
          <GamesIcon size={28} />
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
        ⚽ Play Now
      </button>

      <button
        style={referButtonStyle}
        onClick={() => setShowReferral(true)}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.05)';
          e.currentTarget.style.boxShadow = '0 12px 40px rgba(0, 200, 83, 0.5)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.boxShadow = '0 8px 32px rgba(0, 200, 83, 0.3)';
        }}
      >
        🎁 Refer a Friend
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
        🏆 Leaderboard
      </button>

      {/* Referral Modal */}
      {showReferral && (
        <div style={modalOverlayStyle} onClick={() => setShowReferral(false)}>
          <div style={modalContentStyle} onClick={(e) => e.stopPropagation()}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>🎁</div>
            <h2 style={{ fontSize: '24px', fontWeight: 900, color: '#fff', marginBottom: '8px' }}>
              Refer & Earn Rewards!
            </h2>
            <p style={{ fontSize: '14px', color: 'rgba(255,255,255,0.7)', marginBottom: '24px', lineHeight: 1.5 }}>
              Share StuCred Football Challenge with your friends and unlock amazing rewards!
            </p>
            
            <div style={{ 
              background: 'rgba(0,0,0,0.3)', 
              borderRadius: '16px', 
              padding: '20px', 
              marginBottom: '24px',
              textAlign: 'left'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <span style={{ fontSize: '24px' }}>📱</span>
                <span style={{ color: '#fff', fontWeight: 600 }}>Download the app</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <span style={{ fontSize: '24px' }}>⚽</span>
                <span style={{ color: '#fff', fontWeight: 600 }}>Play the game</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '24px' }}>🎉</span>
                <span style={{ color: '#fff', fontWeight: 600 }}>Unlock amazing rewards</span>
              </div>
            </div>

            <button
              style={{
                ...primaryButtonStyle,
                width: '100%',
                marginBottom: '12px',
              }}
              onClick={handleReferralShare}
            >
              📤 Share Now
            </button>
            
            <button
              style={{
                background: 'transparent',
                border: 'none',
                color: 'rgba(255,255,255,0.5)',
                fontSize: '14px',
                cursor: 'pointer',
                fontFamily: 'Montserrat, sans-serif',
              }}
              onClick={() => setShowReferral(false)}
            >
              Maybe Later
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
