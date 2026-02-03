"""
Endpoints de API para gestión de grupos de chat.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.models import User
from app.schemas.schemas import (
    GroupCreate, GroupResponse, GroupDetailResponse,
    GroupMessageCreate, GroupMessageResponse,
    AddMemberRequest, GroupMemberResponse
)
from app.services.group_service import GroupService


router = APIRouter(prefix="/groups", tags=["groups"])


@router.post("/", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    group_data: GroupCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Crea un nuevo grupo de chat.
    
    El cliente debe:
    1. Generar una clave AES de 256 bits para el grupo
    2. Encriptar esta clave con la clave pública RSA de cada miembro
    3. Enviar el hash SHA-256 de la clave AES
    4. Enviar el diccionario de claves encriptadas
    
    Ejemplo de body:
    ```json
    {
        "name": "Mi Grupo",
        "description": "Descripción opcional",
        "member_ids": [2, 3, 4],
        "encrypted_keys": {
            "1": "base64_encrypted_key_for_admin",
            "2": "base64_encrypted_key_for_member_2",
            "3": "base64_encrypted_key_for_member_3",
            "4": "base64_encrypted_key_for_member_4"
        },
        "group_key_hash": "sha256_hash_of_aes_key"
    }
    ```
    """
    service = GroupService(db)
    
    # Convertir keys de string a int
    encrypted_keys_int = {int(k): v for k, v in group_data.encrypted_keys.items()}
    
    group = await service.create_group(
        group_data=group_data,
        admin_id=current_user.id,
        encrypted_keys=encrypted_keys_int,
        group_key_hash=group_data.group_key_hash,
        ip_address=request.client.host if request.client else None
    )
    
    return GroupResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        admin_id=group.admin_id,
        created_at=group.created_at,
        is_active=group.is_active
    )


@router.get("/", response_model=List[GroupResponse])
async def get_my_groups(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Obtiene todos los grupos del usuario actual"""
    service = GroupService(db)
    groups = await service.get_user_groups(current_user.id)
    
    return [
        GroupResponse(
            id=group.id,
            name=group.name,
            description=group.description,
            admin_id=group.admin_id,
            created_at=group.created_at,
            is_active=group.is_active,
            member_count=len(group.members) if group.members else 0
        )
        for group in groups
    ]


@router.get("/{group_id}", response_model=GroupDetailResponse)
async def get_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Obtiene detalles de un grupo específico"""
    service = GroupService(db)
    group = await service.get_group(group_id, current_user.id)
    members = await service.get_group_members(group_id, current_user.id)
    
    # Cargar datos de usuarios para los miembros
    member_responses = []
    for member in members:
        # Cargar usuario asociado
        await db.refresh(member, ["user"])
        member_responses.append(
            GroupMemberResponse(
                id=member.id,
                user_id=member.user_id,
                username=member.user.username,
                is_admin=member.is_admin,
                can_send_messages=member.can_send_messages,
                can_add_members=member.can_add_members,
                joined_at=member.joined_at
            )
        )
    
    return GroupDetailResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        admin_id=group.admin_id,
        created_at=group.created_at,
        is_active=group.is_active,
        member_count=len(members),
        members=member_responses
    )


@router.get("/{group_id}/members", response_model=List[GroupMemberResponse])
async def get_group_members(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Obtiene los miembros de un grupo"""
    service = GroupService(db)
    members = await service.get_group_members(group_id, current_user.id)
    
    member_responses = []
    for member in members:
        await db.refresh(member, ["user"])
        member_responses.append(
            GroupMemberResponse(
                id=member.id,
                user_id=member.user_id,
                username=member.user.username,
                is_admin=member.is_admin,
                can_send_messages=member.can_send_messages,
                can_add_members=member.can_add_members,
                joined_at=member.joined_at
            )
        )
    
    return member_responses


@router.post("/{group_id}/members", response_model=GroupMemberResponse, status_code=status.HTTP_201_CREATED)
async def add_member(
    group_id: int,
    member_data: AddMemberRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Agrega un miembro al grupo (solo administrador).
    
    El admin debe:
    1. Obtener la clave pública RSA del nuevo miembro
    2. Desencriptar la clave AES del grupo con su propia clave privada
    3. Encriptar la clave AES con la clave pública del nuevo miembro
    4. Enviar la clave encriptada al servidor
    """
    service = GroupService(db)
    member = await service.add_member_by_admin(
        group_id=group_id,
        admin_id=current_user.id,
        new_member_id=member_data.user_id,
        encrypted_group_key=member_data.encrypted_group_key,
        ip_address=request.client.host if request.client else None
    )
    
    await db.refresh(member, ["user"])
    
    return GroupMemberResponse(
        id=member.id,
        user_id=member.user_id,
        username=member.user.username,
        is_admin=member.is_admin,
        can_send_messages=member.can_send_messages,
        can_add_members=member.can_add_members,
        joined_at=member.joined_at
    )


@router.get("/{group_id}/encrypted-key")
async def get_my_encrypted_group_key(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtiene la clave AES del grupo encriptada para el usuario actual.
    El cliente usa esto para desencriptar con su clave privada RSA.
    """
    service = GroupService(db)
    encrypted_key = await service.get_encrypted_group_key(group_id, current_user.id)
    
    return {
        "group_id": group_id,
        "encrypted_group_key": encrypted_key.decode('utf-8')
    }


# ===================== MENSAJES =====================

@router.post("/{group_id}/messages", response_model=GroupMessageResponse, status_code=status.HTTP_201_CREATED)
async def send_group_message(
    group_id: int,
    message_data: GroupMessageCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Envía un mensaje al grupo.
    
    El mensaje debe estar encriptado con la clave AES del grupo.
    """
    if message_data.group_id != group_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El group_id no coincide"
        )
    
    service = GroupService(db)
    message = await service.send_message(
        message_data=message_data,
        sender_id=current_user.id,
        ip_address=request.client.host if request.client else None
    )
    
    await db.refresh(message, ["sender"])
    
    return GroupMessageResponse(
        id=message.id,
        group_id=message.group_id,
        sender_id=message.sender_id,
        sender_username=message.sender.username,
        encrypted_content=message.encrypted_content,
        iv=message.iv,
        signature=message.signature,
        timestamp=message.timestamp,
        nonce=message.nonce
    )


@router.get("/{group_id}/messages", response_model=List[GroupMessageResponse])
async def get_group_messages(
    group_id: int,
    limit: int = 50,
    before_id: int = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtiene mensajes de un grupo.
    
    Parámetros de paginación:
    - limit: Número máximo de mensajes a retornar
    - before_id: Obtener mensajes anteriores a este ID (paginación)
    """
    service = GroupService(db)
    messages = await service.get_group_messages(
        group_id=group_id,
        user_id=current_user.id,
        limit=limit,
        before_id=before_id
    )
    
    message_responses = []
    for message in messages:
        await db.refresh(message, ["sender"])
        message_responses.append(
            GroupMessageResponse(
                id=message.id,
                group_id=message.group_id,
                sender_id=message.sender_id,
                sender_username=message.sender.username,
                encrypted_content=message.encrypted_content,
                iv=message.iv,
                signature=message.signature,
                timestamp=message.timestamp,
                nonce=message.nonce
            )
        )
    
    return message_responses
