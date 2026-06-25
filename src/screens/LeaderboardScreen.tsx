import React from 'react';
import type { LeaderboardEntry } from '../types/game';

interface LeaderboardScreenProps {
  entries: LeaderboardEntry[];
  onBack: () => void;
}

export default function LeaderboardScreen({ entries, onBack }: LeaderboardScreenProps) {
  const containerStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    background: 'linear-gradient(135deg, #0a1628 0%, #1a3a5c 50%, #0a1628 100%)',
    padding: '20px',
  };

  const headerStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    marginBottom: '24px',
    gap: '16px',
  };

  const backButtonStyle: React.CSSProperties = {
    width: '40px',
    height: '40px',
    borderRadius: '50%',
    border: '2px solid rgba(255, 255, 255, 0.3)',
    background: 'rgba(255, 255, 255, 0.1)',
    color: '#fff',
    fontSize: '20px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.3s ease',
  };

  const titleStyle: React.CSSProperties = {
    fontSize: '24px',
    fontWeight: 900,
    color: '#fff',
    flex: 1,
  };

  const subtitleStyle: React.CSSProperties = {
    fontSize: '12px',
    fontWeight: 600,
    color: '#f7931e',
    textTransform: 'uppercase',
    letterSpacing: '2px',
  };

  const listStyle: React.CSSProperties = {
    flex: 1,
    overflow: 'auto',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  };

  const entryStyle = (isTop3: boolean, isUser: boolean): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    padding: '16px',
    borderRadius: '16px',
    background: isUser
      ? 'linear-gradient(135deg, rgba(255, 107, 53, 0.3) 0%, rgba(247, 147, 30, 0.2) 100%)'
      : isTop3
      ? 'linear-gradient(135deg, rgba(255, 215, 0, 0.15) 0%, rgba(255, 215, 0, 0.05) 100%)'
      : 'rgba(255, 255, 255, 0.05)',
    border: isUser
      ? '2px solid rgba(255, 107, 53, 0.5)'
      : isTop3
      ? '1px solid rgba(255, 215, 0, 0.3)'
      : '1px solid rgba(255, 255, 255, 0.1)',
    transition: 'all 0.3s ease',
  });

  const rankStyle = (rank: number): React.CSSProperties => ({
    width: '40px',
    height: '40px',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '18px',
    fontWeight: 900,
    marginRight: '16px',
    background:
      rank === 1
        ? 'linear-gradient(135deg, #ffd700 0%, #ff6b35 100%)'
        : rank === 2
        ? 'linear-gradient(135deg, #c0c0c0 0%, #e8e8e8 100%)'
        : rank === 3
        ? 'linear-gradient(135deg, #cd7f32 0%, #daa520 100%)'
        : 'rgba(255, 255, 255, 0.1)',
    color: rank <= 3 ? '#000' : '#fff',
  });

  const nameStyle: React.CSSProperties = {
    flex: 1,
    fontSize: '16px',
    fontWeight: 700,
    color: '#fff',
  };

  const scoreStyle: React.CSSProperties = {
    fontSize: '20px',
    fontWeight: 900,
    color: '#f7931e',
  };

  const rewardBannerStyle: React.CSSProperties = {
    background: 'linear-gradient(135deg, rgba(255, 215, 0, 0.2) 0%, rgba(255, 107, 53, 0.2) 100%)',
    borderRadius: '16px',
    padding: '16px',
    marginBottom: '16px',
    border: '1px solid rgba(255, 215, 0, 0.3)',
    textAlign: 'center',
  };

  const rewardTextStyle: React.CSSProperties = {
    fontSize: '14px',
    fontWeight: 600,
    color: '#ffd700',
  };

  const topEntries = entries.slice(0, 3);
  const hasReward = topEntries.some(e => e.name === 'You');

  return (
    <div style={containerStyle}>
      <div style={headerStyle}>
        <button
          style={backButtonStyle}
          onClick={onBack}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.2)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.1)';
          }}
        >
          ←
        </button>
        <div>
          <div style={titleStyle}>Leaderboard</div>
          <div style={subtitleStyle}>Daily Rankings</div>
        </div>
      </div>

      {hasReward && (
        <div style={rewardBannerStyle}>
          <div style={rewardTextStyle}>🎉 Congratulations! You won a Scratch Card Reward!</div>
        </div>
      )}

      <div style={listStyle}>
        {entries.map((entry) => (
          <div
            key={`${entry.rank}-${entry.name}`}
            style={entryStyle(entry.rank <= 3, entry.name === 'You')}
          >
            <div style={rankStyle(entry.rank)}>
              {entry.rank === 1 ? '🥇' : entry.rank === 2 ? '🥈' : entry.rank === 3 ? '🥉' : entry.rank}
            </div>
            <div style={nameStyle}>
              {entry.name}
              {entry.name === 'You' && (
                <span style={{ fontSize: '12px', color: '#f7931e', marginLeft: '8px' }}>(You)</span>
              )}
            </div>
            <div style={scoreStyle}>{entry.score}</div>
          </div>
        ))}

        {entries.length === 0 && (
          <div style={{ textAlign: 'center', padding: '40px', color: 'rgba(255, 255, 255, 0.5)' }}>
            No scores yet. Be the first to play!
          </div>
        )}
      </div>

      <div style={{ marginTop: '16px', textAlign: 'center' }}>
        <div style={{ fontSize: '12px', color: 'rgba(255, 255, 255, 0.5)' }}>
          Top 3 players win scratch card rewards daily
        </div>
        <div style={{ fontSize: '11px', color: 'rgba(255, 255, 255, 0.3)', marginTop: '4px' }}>
          Resets every 24 hours
        </div>
      </div>
    </div>
  );
}
