import React from 'react';
import { useGameState } from './hooks/useGameState';
import MenuScreen from './screens/MenuScreen';
import GameScreen from './screens/GameScreen';
import ResultScreen from './screens/ResultScreen';
import LeaderboardScreen from './screens/LeaderboardScreen';

export default function App() {
  const {
    gameState,
    gameConfig,
    timeRemaining,
    isPlaying,
    startGame,
    endGame,
    processShot,
    setScreen,
    setTimeRemaining,
    setIsPlaying,
  } = useGameState();

  const appStyle: React.CSSProperties = {
    width: '100vw',
    height: '100vh',
    backgroundColor: '#0a1628',
    color: '#fff',
    overflow: 'hidden',
    fontFamily: 'Montserrat, sans-serif',
    position: 'relative',
  };

  return (
    <div style={appStyle}>
      {gameState.screen === 'menu' && (
        <MenuScreen
          highScore={gameState.highScore}
          totalGames={gameState.totalGamesPlayed}
          onStartGame={startGame}
          onShowLeaderboard={() => setScreen('leaderboard')}
        />
      )}

      {gameState.screen === 'game' && (
        <GameScreen
          gameConfig={gameConfig}
          timeRemaining={timeRemaining}
          isPlaying={isPlaying}
          score={gameState.score}
          shotsTaken={gameState.shotsTaken}
          shotsMade={gameState.shotsMade}
          currentStreak={gameState.currentStreak}
          onShot={processShot}
          onGameOver={endGame}
          setTimeRemaining={setTimeRemaining}
          setIsPlaying={setIsPlaying}
        />
      )}

      {gameState.screen === 'result' && (
        <ResultScreen
          score={gameState.score}
          highScore={gameState.highScore}
          shotsTaken={gameState.shotsTaken}
          shotsMade={gameState.shotsMade}
          bestStreak={gameState.bestStreak}
          onPlayAgain={startGame}
          onBackToMenu={() => setScreen('menu')}
          onShowLeaderboard={() => setScreen('leaderboard')}
        />
      )}

      {gameState.screen === 'leaderboard' && (
        <LeaderboardScreen
          entries={gameState.dailyLeaderboard}
          onBack={() => setScreen('menu')}
        />
      )}
    </div>
  );
}
