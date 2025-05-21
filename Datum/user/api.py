from .models import ChatRoom, Message
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


@api_view(['GET'])
def get_or_create_chat(request):
    user_id = request.GET.get('user_id')
    other_user = get_object_or_404(User, id=user_id)

    room = ChatRoom.objects.filter(
        models.Q(user1=request.user, user2=other_user) |
        models.Q(user1=other_user, user2=request.user)
    ).first()

    if not room:
        room = ChatRoom.objects.create(user1=request.user, user2=other_user)

    return Response({'room_id': room.id})


@api_view(['GET'])
def get_messages(request):
    room_id = request.GET.get('room_id')
    room = get_object_or_404(ChatRoom, id=room_id)
    messages = Message.objects.filter(room=room).order_by('timestamp')

    return Response([{
        'sender': msg.sender.id,
        'content': msg.content,
        'timestamp': msg.timestamp
    } for msg in messages])