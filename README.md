# StuCred Football Challenge

A football-themed mini-game integrated within the StuCred app for FIFA season engagement.

## Features

- ⚽ **Penalty Shootout Gameplay** - Tap targets to score goals while avoiding the goalkeeper
- 🔥 **Streak System** - Build combos for bonus points
- 🏆 **Daily Leaderboard** - Top 3 players win scratch card rewards
- 📊 **Analytics** - Track plays, scores, and performance
- 🎨 **StuCred Branding** - Custom jersey, colors, and stadium theme

## Game Mechanics

- **Duration**: 30 seconds per game
- **Unlimited plays** per day
- **Daily leaderboard reset** every 24 hours
- **Scoring**: Hit targets (1x, 2x, 3x) with combo multipliers
- **Goalkeeper AI**: Moves to block your shots

## Tech Stack

- React + TypeScript
- Vite
- Capacitor (for Android APK)
- GitHub Actions (CI/CD)

## Development

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Build for production
npm run build

# Add Android platform
npm run android

# Sync Capacitor
npm run sync
```

## Building APK

The APK is automatically built via GitHub Actions when you push a tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Or manually trigger the workflow from the GitHub Actions tab.

## Download

Latest APK available in [GitHub Releases](../../releases).
