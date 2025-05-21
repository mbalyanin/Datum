import json
import time
from datetime import datetime
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model

from .models import Message

User = get_user_model()


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        if self.user.is_anonymous:
            await self.close()
        else:
            # Создаем имя комнаты на основе ID пользователя
            self.room_name = f'user_{self.user.id}'
            self.room_group_name = self.room_name  # Можно использовать другое имя если нужно

            # Добавляем канал в группу
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            await self.accept()

    async def disconnect(self, close_code):
        # Удаляем канал из группы только если room_group_name существует
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )

    async def receive(self, text_data=None, bytes_data=None):
        try:
            data = json.loads(text_data)

            if data.get('type') != 'chat_message':
                return

            if not all(k in data for k in ['receiver_id', 'content']):
                raise ValueError("Missing required fields")

            message_data = {
                'type': 'chat_message',
                'sender_id': self.user.id,
                'receiver_id': data['receiver_id'],
                'content': data['content'],
                'timestamp': datetime.now().isoformat()
            }

            await self.save_message(message_data)

            # Отправляем получателю
            await self.channel_layer.group_send(
                f"user_{message_data['receiver_id']}",
                {
                    'type': 'chat.message',
                    'message': message_data
                }
            )

        except Exception as e:
            print(f"Error: {str(e)}")

    async def chat_message(self, event):
        """
        Отправка сообщения через WebSocket.
        Не используем currentChatId - он есть только на клиенте.
        """
        await self.send(text_data=json.dumps({
            'type': 'chat.message',
            'message': event['message'],
            'is_realtime': True
        }))

    @database_sync_to_async
    def save_message(self, message_data):
        sender = User.objects.get(id=message_data['sender_id'])
        receiver = User.objects.get(id=message_data['receiver_id'])

        return Message.objects.create(
            sender=sender,
            receiver=receiver,
            content=message_data['content'],
            timestamp=message_data['timestamp']
        )