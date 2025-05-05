const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cors({
    origin: ['http://localhost:8080', 'https://your-frontend-domain.com'], // Update with your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Initialize database tables
async function initializeDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS games (
                id SERIAL PRIMARY KEY,
                player1 VARCHAR(50) NOT NULL,
                player2 VARCHAR(50),
                board JSONB NOT NULL,
                current_player CHAR(1) NOT NULL,
                status VARCHAR(20) NOT NULL,
                winner CHAR(1)
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS invitations (
                id SERIAL PRIMARY KEY,
                from_username VARCHAR(50) NOT NULL,
                to_username VARCHAR(50) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Database tables initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
    }
}

// Run database initialization when the server starts
initializeDatabase();

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requerido' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.user = user;
        next();
    });
};

// User Registration
app.post('/api/users/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña requeridos' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
            [username, hashedPassword]
        );
        res.status(201).json({ message: 'Usuario registrado' });
    } catch (error) {
        if (error.code === '23505') {
            res.status(400).json({ message: 'El usuario ya existe' });
        } else {
            res.status(500).json({ message: 'Error al registrar usuario' });
        }
    }
});

// User Login
app.post('/api/users/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error al iniciar sesión' });
    }
});

// Send Invitation
app.post('/api/invitations', authenticateToken, async (req, res) => {
    const { from, to } = req.body;
    if (req.user.username !== from) {
        return res.status(403).json({ message: 'No autorizado' });
    }
    try {
        const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [to]);
        if (!userCheck.rows[0]) return res.status(404).json({ message: 'Usuario no encontrado' });
        const result = await pool.query(
            'INSERT INTO invitations (from_username, to_username) VALUES ($1, $2) RETURNING id',
            [from, to]
        );
        res.json({ invitationId: result.rows[0].id });
    } catch (error) {
        res.status(500).json({ message: 'Error al enviar la invitación' });
    }
});

// Get Pending Invitations
app.get('/api/invitations', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM invitations WHERE to_username = $1 AND status = $2',
            [req.user.username, 'pending']
        );
        res.json({ invitations: result.rows });
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener invitaciones' });
    }
});

// Accept Invitation
app.post('/api/invitations/:id/accept', authenticateToken, async (req, res) => {
    const { player } = req.body;
    const invitationId = req.params.id;
    if (req.user.username !== player) {
        return res.status(403).json({ message: 'No autorizado' });
    }
    try {
        const result = await pool.query(
            'SELECT * FROM invitations WHERE id = $1 AND to_username = $2 AND status = $3',
            [invitationId, player, 'pending']
        );
        const invitation = result.rows[0];
        if (!invitation) return res.status(404).json({ message: 'Invitación no encontrada' });
        const gameResult = await pool.query(
            'INSERT INTO games (player1, player2, board, current_player, status) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [invitation.from_username, player, JSON.stringify(['', '', '', '', '', '', '', '', '']), 'X', 'active']
        );
        await pool.query('UPDATE invitations SET status = $1 WHERE id = $2', ['accepted', invitationId]);
        res.json({ gameId: gameResult.rows[0].id });
    } catch (error) {
        res.status(500).json({ message: 'Error al aceptar la invitación' });
    }
});

// Reject Invitation
app.post('/api/invitations/:id/reject', authenticateToken, async (req, res) => {
    const invitationId = req.params.id;
    try {
        const result = await pool.query(
            'SELECT * FROM invitations WHERE id = $1 AND to_username = $2 AND status = $3',
            [invitationId, req.user.username, 'pending']
        );
        if (!result.rows[0]) return res.status(404).json({ message: 'Invitación no encontrada' });
        await pool.query('UPDATE invitations SET status = $1 WHERE id = $2', ['rejected', invitationId]);
        res.json({ message: 'Invitación rechazada' });
    } catch (error) {
        res.status(500).json({ message: 'Error al rechazar la invitación' });
    }
});

// Create Game
app.post('/api/games', authenticateToken, async (req, res) => {
    const { player1 } = req.body;
    if (req.user.username !== player1) {
        return res.status(403).json({ message: 'No autorizado' });
    }
    try {
        const result = await pool.query(
            'INSERT INTO games (player1, board, current_player, status) VALUES ($1, $2, $3, $4) RETURNING id',
            [player1, JSON.stringify(['', '', '', '', '', '', '', '', '']), 'X', 'active']
        );
        res.json({ gameId: result.rows[0].id });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear el juego' });
    }
});

// Join Game
app.post('/api/games/:id/join', authenticateToken, async (req, res) => {
    const { player2 } = req.body;
    const gameId = req.params.id;
    if (req.user.username !== player2) {
        return res.status(403).json({ message: 'No autorizado' });
    }
    try {
        const result = await pool.query('SELECT * FROM games WHERE id = $1', [gameId]);
        const game = result.rows[0];
        if (!game) return res.status(404).json({ message: 'Juego no encontrado' });
        if (game.player2) return res.status(400).json({ message: 'El juego ya tiene dos jugadores' });
        await pool.query('UPDATE games SET player2 = $1 WHERE id = $2', [player2, gameId]);
        res.json({ message: 'Unido al juego' });
    } catch (error) {
        res.status(500).json({ message: 'Error al unirse al juego' });
    }
});

// Make Move
app.post('/api/games/:id/move', authenticateToken, async (req, res) => {
    const { player, board, currentPlayer } = req.body;
    const gameId = req.params.id;
    try {
        const result = await pool.query('SELECT * FROM games WHERE id = $1', [gameId]);
        const game = result.rows[0];
        if (!game) return res.status(404).json({ message: 'Juego no encontrado' });
        if (game.player1 !== player && game.player2 !== player) {
            return res.status(403).json({ message: 'No autorizado' });
        }
        let status = 'active';
        let winner = null;
        if (checkWin(board, currentPlayer)) {
            status = 'won';
            winner = currentPlayer;
        } else if (board.every(cell => cell !== '')) {
            status = 'draw';
        }
        await pool.query(
            'UPDATE games SET board = $1, current_player = $2, status = $3, winner = $4 WHERE id = $5',
            [JSON.stringify(board), currentPlayer === 'X' ? 'O' : 'X', status, winner, gameId]
        );
        res.json({ message: 'Movimiento registrado' });
    } catch (error) {
        res.status(500).json({ message: 'Error al procesar el movimiento' });
    }
});

// Get Game State
app.get('/api/games/:id', authenticateToken, async (req, res) => {
    const gameId = req.params.id;
    try {
        const result = await pool.query('SELECT * FROM games WHERE id = $1', [gameId]);
        const game = result.rows[0];
        if (!game) return res.status(404).json({ message: 'Juego no encontrado' });
        if (game.player1 !== req.user.username && game.player2 !== req.user.username) {
            return res.status(403).json({ message: 'No autorizado' });
        }
        res.json({
            board: JSON.parse(game.board),
            currentPlayer: game.current_player,
            status: game.status,
            winner: game.winner
        });
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener el estado del juego' });
    }
});

// Helper function to check win
function checkWin(board, player) {
    const winConditions = [
        [0, 1, 2], [3, 4, 5], [6, 7, 8],
        [0, 3, 6], [1, 4, 7], [2, 5, 8],
        [0, 4, 8], [2, 4, 6]
    ];
    return winConditions.some(condition =>
        condition.every(index => board[index] === player)
    );
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
