const express = require('express');
const { Groq } = require('groq-sdk');
const path = require('path');

const app = express();
app.use(express.json());

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const userSessions = {};
const freeMessageCounts = {};

app.get('/ping', (req, res) => {
    res.status(200).send('AFK AI Server is alive!');
});

app.post('/api/chat', async (req, res) => {
    try {
        const { username, message, isAdmin, adminPassword } = req.body;

        if (!username || !message) {
            return res.status(400).json({ error: "Nom d'utilisateur et message requis." });
        }

        let userIsAdmin = false;
        if (isAdmin && adminPassword === process.env.ADMIN_SECRET) {
            userIsAdmin = true;
        }

        if (!userIsAdmin) {
            if (!freeMessageCounts[username]) {
                freeMessageCounts[username] = 0;
            }
            if (freeMessageCounts[username] >= 10) {
                return res.status(429).json({
                    limitReached: true,
                    error: "Limite gratuite atteinte (10/10). Veuillez patienter, utiliser un autre compte ou passer à la version Premium."
                });
            }
            freeMessageCounts[username]++;
        }

        if (!userSessions[username]) {
            userSessions[username] = [
                { role: "system", content: "Tu es AFK AI, un assistant virtuel ultra-performant, professionnel et courtois." }
            ];
        }

        userSessions[username].push({ role: "user", content: message });

        // MODIFICATION ICI : Utilisation de qwen/qwen3.8-27b
        const chatCompletion = await groq.chat.completions.create({
            messages: userSessions[username],
            model: "qwen/qwen3.8-27b",
            temperature: 0.7,
        });

        const botReply = chatCompletion.choices[0].message.content;
        userSessions[username].push({ role: "assistant", content: botReply });

        res.json({ reply: botReply, isAdmin: userIsAdmin });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`AFK AI en cours d'exécution sur le port ${PORT}`);
});
