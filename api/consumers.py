# api/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']
        self.room_group_name = f'chat_{self.room_id}'
        
        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()
        
        # Send connection confirmation
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': 'You are now connected!'
        }))
    
    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message_type = text_data_json.get('type')
        
        if message_type == 'chat_message':
            message_content = text_data_json.get('message')
            sender_id = text_data_json.get('sender_id')
            
            # Save message to database
            message = await self.save_message(message_content, sender_id)
            
            # Send message to room group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message_content,
                    'sender_id': sender_id,
                    'message_id': message.id,
                    'timestamp': str(message.created_at)
                }
            )
        
        elif message_type == 'typing':
            # Broadcast typing status
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'typing_indicator',
                    'user_id': text_data_json.get('user_id'),
                    'is_typing': text_data_json.get('is_typing')
                }
            )
    
    async def chat_message(self, event):
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': event['message'],
            'sender_id': event['sender_id'],
            'message_id': event['message_id'],
            'timestamp': event['timestamp']
        }))
    
    async def typing_indicator(self, event):
        # Send typing indicator
        await self.send(text_data=json.dumps({
            'type': 'typing',
            'user_id': event['user_id'],
            'is_typing': event['is_typing']
        }))
    
    @database_sync_to_async
    def save_message(self, content, sender_id):
        try:
            room = ChatRoom.objects.get(id=self.room_id)
            sender = User.objects.get(id=sender_id)
            
            message = Message.objects.create(
                room=room,
                sender=sender,
                content=content
            )
            
            # Update room's last message time
            room.last_message_time = message.created_at
            room.save()
            
            return message
        except (ChatRoom.DoesNotExist, User.DoesNotExist):
            return None