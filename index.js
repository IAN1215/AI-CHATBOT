require('dotenv').config();
const express = require('express');
const { Client, middleware } = require('@line/bot-sdk');
const axios = require('axios');

const config = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET
};

const app = express();
const lineClient = new Client(config);

app.post('/webhook', middleware(config), async (req, res) => {
  const events = req.body.events;
  const results = await Promise.all(events.map(handleEvent));
  res.json(results);
});

async function handleEvent(event) {
  if (event.type !== 'message' || event.message.type !== 'text') {
    return null;
  }

  const userMessage = event.message.text;

  try {
    const reply = await getGPTReply(userMessage);

    return lineClient.replyMessage(event.replyToken, {
      type: 'text',
      text: reply
    });

  } catch (err) {
    console.error('GPT 錯誤：', err);
    return lineClient.replyMessage(event.replyToken, {
      type: 'text',
      text: '抱歉，AI 暫時無法回覆，請稍後再試～'
    });
  }
}

async function getGPTReply(userInput) {
  const response = await axios.post(
    'https://api.openai.com/v1/chat/completions',
    {
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'user', content: userInput }]
    },
    {
      headers: {
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    }
  );

  return response.data.choices[0].message.content.trim();
}

app.listen(3000, () => {
  console.log('KAICHUAN Line Bot 已啟動於 http://localhost:3000');
});
