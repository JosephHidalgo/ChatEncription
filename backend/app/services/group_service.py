"""
Servicio de gestión de grupos de chat.
Maneja creación, administración y mensajería de grupos con encriptación AES compartida.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
from datetime import datetime, timedelta
from typing import Optional, List, Dict
import secrets
import hashlib

from app.models.models import (
    Group, GroupMember, GroupMessage, GroupInviteCode, User, AuditLog
)
from app.schemas.schemas import (
    GroupCreate, GroupUpdate, GroupMessageCreate, 
    AddMemberRequest, InviteCodeCreate, JoinGroupWithCodeRequest
)
from app.core.config import settings


class GroupService:
    """Servicio de gestión de grupos con encriptación híbrida"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_group(
        self,
        group_data: GroupCreate,
        admin_id: int,
        encrypted_keys: Dict[int, str],  # {user_id: encrypted_group_key}
        group_key_hash: str,
        ip_address: Optional[str] = None
    ) -> Group:
        """
        Crea un nuevo grupo de chat.
        
        Flujo:
        1. Cliente genera clave AES para el grupo
        2. Cliente encripta la clave AES con RSA de cada miembro
        3. Cliente envía las claves encriptadas al servidor
        4. Servidor almacena las claves encriptadas para cada miembro
        
        Args:
            group_data: Datos del grupo
            admin_id: ID del administrador
            encrypted_keys: Diccionario {user_id: encrypted_group_key}
            group_key_hash: Hash SHA-256 de la clave AES del grupo
            ip_address: IP del cliente
        
        Returns:
            Grupo creado
        """
        # Verificar que el admin existe
        result = await self.db.execute(
            select(User).where(User.id == admin_id)
        )
        admin_user = result.scalar_one_or_none()
        if not admin_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario administrador no encontrado"
            )
        
        # Verificar que todos los miembros existen
        if group_data.member_ids:
            result = await self.db.execute(
                select(User).where(User.id.in_(group_data.member_ids))
            )
            members = result.scalars().all()
            if len(members) != len(group_data.member_ids):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Algunos usuarios no existen"
                )
        
        # Crear grupo
        new_group = Group(
            name=group_data.name,
            description=group_data.description,
            admin_id=admin_id,
            group_key_hash=group_key_hash
        )
        
        self.db.add(new_group)
        await self.db.flush()  # Para obtener el ID
        
        # Agregar admin como miembro
        admin_encrypted_key = encrypted_keys.get(admin_id)
        if not admin_encrypted_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Falta clave encriptada del administrador"
            )
        
        admin_member = GroupMember(
            group_id=new_group.id,
            user_id=admin_id,
            encrypted_group_key=admin_encrypted_key.encode('utf-8'),
            is_admin=True,
            can_add_members=True
        )
        self.db.add(admin_member)
        
        # Agregar miembros iniciales
        for member_id in group_data.member_ids:
            if member_id == admin_id:
                continue  # Ya agregado
            
            encrypted_key = encrypted_keys.get(member_id)
            if not encrypted_key:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Falta clave encriptada para usuario {member_id}"
                )
            
            member = GroupMember(
                group_id=new_group.id,
                user_id=member_id,
                encrypted_group_key=encrypted_key.encode('utf-8'),
                is_admin=False
            )
            self.db.add(member)
        
        await self.db.commit()
        await self.db.refresh(new_group)
        
        # Auditoría
        await self._create_audit_log(
            user_id=admin_id,
            action=f"Grupo '{group_data.name}' creado",
            action_type="GROUP_CREATED",
            ip_address=ip_address,
            details=f"Grupo ID: {new_group.id}, Miembros: {len(group_data.member_ids) + 1}"
        )
        
        return new_group
    
    async def get_group(self, group_id: int, user_id: int) -> Group:
        """
        Obtiene un grupo si el usuario es miembro.
        
        Args:
            group_id: ID del grupo
            user_id: ID del usuario solicitante
        
        Returns:
            Grupo
        """
        result = await self.db.execute(
            select(Group).where(Group.id == group_id)
        )
        group = result.scalar_one_or_none()
        
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Grupo no encontrado"
            )
        
        # Verificar que el usuario es miembro
        is_member = await self._is_member(group_id, user_id)
        if not is_member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No eres miembro de este grupo"
            )
        
        return group
    
    async def get_user_groups(self, user_id: int) -> List[Group]:
        """
        Obtiene todos los grupos de un usuario.
        
        Args:
            user_id: ID del usuario
        
        Returns:
            Lista de grupos
        """
        result = await self.db.execute(
            select(Group)
            .join(GroupMember)
            .where(
                and_(
                    GroupMember.user_id == user_id,
                    Group.is_active == True
                )
            )
            .options(selectinload(Group.members))
            .order_by(Group.created_at.desc())
        )
        return result.scalars().all()
    
    async def get_group_members(self, group_id: int, user_id: int) -> List[GroupMember]:
        """
        Obtiene los miembros de un grupo.
        
        Args:
            group_id: ID del grupo
            user_id: ID del usuario solicitante
        
        Returns:
            Lista de miembros
        """
        # Verificar que el usuario es miembro
        is_member = await self._is_member(group_id, user_id)
        if not is_member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No eres miembro de este grupo"
            )
        
        result = await self.db.execute(
            select(GroupMember)
            .where(GroupMember.group_id == group_id)
            .order_by(GroupMember.joined_at.asc())
        )
        return result.scalars().all()
    
    async def add_member_by_admin(
        self,
        group_id: int,
        admin_id: int,
        new_member_id: int,
        encrypted_group_key: str,
        ip_address: Optional[str] = None
    ) -> GroupMember:
        """
        Agrega un miembro al grupo (solo administrador).
        
        Args:
            group_id: ID del grupo
            admin_id: ID del administrador
            new_member_id: ID del nuevo miembro
            encrypted_group_key: Clave AES encriptada con RSA del nuevo miembro
            ip_address: IP del cliente
        
        Returns:
            Miembro agregado
        """
        # Verificar que el grupo existe
        result = await self.db.execute(
            select(Group).where(Group.id == group_id)
        )
        group = result.scalar_one_or_none()
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Grupo no encontrado"
            )
        
        # Verificar que el usuario es administrador
        is_admin = await self._is_admin(group_id, admin_id)
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Solo el administrador puede agregar miembros"
            )
        
        # Verificar que el nuevo miembro existe
        result = await self.db.execute(
            select(User).where(User.id == new_member_id)
        )
        new_user = result.scalar_one_or_none()
        if not new_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        # Verificar que no es ya miembro
        is_already_member = await self._is_member(group_id, new_member_id)
        if is_already_member:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El usuario ya es miembro del grupo"
            )
        
        # Agregar miembro
        new_member = GroupMember(
            group_id=group_id,
            user_id=new_member_id,
            encrypted_group_key=encrypted_group_key.encode('utf-8'),
            is_admin=False
        )
        
        self.db.add(new_member)
        await self.db.commit()
        await self.db.refresh(new_member)
        
        # Auditoría
        await self._create_audit_log(
            user_id=admin_id,
            action=f"Miembro {new_user.username} agregado al grupo {group.name}",
            action_type="MEMBER_ADDED",
            ip_address=ip_address,
            details=f"Grupo ID: {group_id}, Nuevo miembro ID: {new_member_id}"
        )
        
        return new_member
    
    async def generate_invite_code(
        self,
        group_id: int,
        admin_id: int,
        code_data: InviteCodeCreate,
        ip_address: Optional[str] = None
    ) -> GroupInviteCode:
        """
        Genera un código de invitación para el grupo (solo administrador).
        
        Args:
            group_id: ID del grupo
            admin_id: ID del administrador
            code_data: Datos del código
            ip_address: IP del cliente
        
        Returns:
            Código de invitación generado
        """
        # Verificar que el usuario es administrador
        is_admin = await self._is_admin(group_id, admin_id)
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Solo el administrador puede generar códigos"
            )
        
        # Generar código único
        code = secrets.token_urlsafe(16)
        
        # Calcular fecha de expiración
        expires_at = None
        if code_data.expires_in_hours:
            expires_at = datetime.utcnow() + timedelta(hours=code_data.expires_in_hours)
        
        # Crear código de invitación
        invite_code = GroupInviteCode(
            group_id=group_id,
            created_by=admin_id,
            code=code,
            max_uses=code_data.max_uses,
            expires_at=expires_at
        )
        
        self.db.add(invite_code)
        await self.db.commit()
        await self.db.refresh(invite_code)
        
        # Auditoría
        await self._create_audit_log(
            user_id=admin_id,
            action=f"Código de invitación generado para grupo ID {group_id}",
            action_type="INVITE_CODE_CREATED",
            ip_address=ip_address,
            details=f"Código: {code}, Max usos: {code_data.max_uses}, Expira: {expires_at}"
        )
        
        return invite_code
    
    async def join_with_code(
        self,
        user_id: int,
        join_data: JoinGroupWithCodeRequest,
        ip_address: Optional[str] = None
    ) -> GroupMember:
        """
        Une a un usuario a un grupo mediante código de invitación.
        
        Args:
            user_id: ID del usuario
            join_data: Datos para unirse (código y clave encriptada)
            ip_address: IP del cliente
        
        Returns:
            Miembro creado
        """
        # Buscar código de invitación
        result = await self.db.execute(
            select(GroupInviteCode).where(
                GroupInviteCode.code == join_data.code
            )
        )
        invite_code = result.scalar_one_or_none()
        
        if not invite_code:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Código de invitación no válido"
            )
        
        # Verificar que el código está activo
        if not invite_code.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código de invitación desactivado"
            )
        
        # Verificar expiración
        if invite_code.expires_at and invite_code.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código de invitación expirado"
            )
        
        # Verificar usos máximos
        if invite_code.max_uses and invite_code.current_uses >= invite_code.max_uses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código de invitación agotado"
            )
        
        # Verificar que no es ya miembro
        is_already_member = await self._is_member(invite_code.group_id, user_id)
        if is_already_member:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ya eres miembro de este grupo"
            )
        
        # Agregar miembro
        new_member = GroupMember(
            group_id=invite_code.group_id,
            user_id=user_id,
            encrypted_group_key=join_data.encrypted_group_key.encode('utf-8'),
            is_admin=False
        )
        
        # Incrementar contador de usos
        invite_code.current_uses += 1
        
        self.db.add(new_member)
        await self.db.commit()
        await self.db.refresh(new_member)
        
        # Auditoría
        await self._create_audit_log(
            user_id=user_id,
            action=f"Usuario unido al grupo ID {invite_code.group_id} con código",
            action_type="MEMBER_JOINED",
            ip_address=ip_address,
            details=f"Código usado: {join_data.code}"
        )
        
        return new_member
    
    async def get_encrypted_group_key(
        self,
        group_id: int,
        user_id: int
    ) -> bytes:
        """
        Obtiene la clave AES del grupo encriptada para un usuario.
        
        Args:
            group_id: ID del grupo
            user_id: ID del usuario
        
        Returns:
            Clave AES encriptada
        """
        result = await self.db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id == user_id
                )
            )
        )
        member = result.scalar_one_or_none()
        
        if not member:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No eres miembro de este grupo"
            )
        
        return member.encrypted_group_key
    
    async def send_message(
        self,
        message_data: GroupMessageCreate,
        sender_id: int,
        ip_address: Optional[str] = None
    ) -> GroupMessage:
        """
        Envía un mensaje al grupo.
        
        Args:
            message_data: Datos del mensaje
            sender_id: ID del remitente
            ip_address: IP del cliente
        
        Returns:
            Mensaje creado
        """
        # Verificar que el usuario es miembro
        is_member = await self._is_member(message_data.group_id, sender_id)
        if not is_member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No eres miembro de este grupo"
            )
        
        # Verificar permisos
        result = await self.db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == message_data.group_id,
                    GroupMember.user_id == sender_id
                )
            )
        )
        member = result.scalar_one_or_none()
        
        if not member.can_send_messages:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permiso para enviar mensajes"
            )
        
        # Crear mensaje
        nonce = secrets.token_urlsafe(32)
        new_message = GroupMessage(
            group_id=message_data.group_id,
            sender_id=sender_id,
            encrypted_content=message_data.encrypted_content,
            iv=message_data.iv,
            signature=message_data.signature,
            nonce=nonce
        )
        
        self.db.add(new_message)
        await self.db.commit()
        await self.db.refresh(new_message)
        
        return new_message
    
    async def get_group_messages(
        self,
        group_id: int,
        user_id: int,
        limit: int = 50,
        before_id: Optional[int] = None
    ) -> List[GroupMessage]:
        """
        Obtiene mensajes de un grupo.
        
        Args:
            group_id: ID del grupo
            user_id: ID del usuario solicitante
            limit: Límite de mensajes
            before_id: Mensaje ID para paginación
        
        Returns:
            Lista de mensajes
        """
        # Verificar que el usuario es miembro
        is_member = await self._is_member(group_id, user_id)
        if not is_member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No eres miembro de este grupo"
            )
        
        query = select(GroupMessage).where(GroupMessage.group_id == group_id)
        
        if before_id:
            query = query.where(GroupMessage.id < before_id)
        
        query = query.order_by(GroupMessage.timestamp.desc()).limit(limit)
        
        result = await self.db.execute(query)
        messages = result.scalars().all()
        
        return list(reversed(messages))  # Orden cronológico
    
    # ===================== HELPERS =====================
    
    async def _is_member(self, group_id: int, user_id: int) -> bool:
        """Verifica si un usuario es miembro de un grupo"""
        result = await self.db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id == user_id
                )
            )
        )
        return result.scalar_one_or_none() is not None
    
    async def _is_admin(self, group_id: int, user_id: int) -> bool:
        """Verifica si un usuario es administrador de un grupo"""
        result = await self.db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id == user_id,
                    GroupMember.is_admin == True
                )
            )
        )
        return result.scalar_one_or_none() is not None
    
    async def _create_audit_log(
        self,
        action: str,
        action_type: str,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        details: Optional[str] = None
    ):
        """Crea un registro en el log de auditoría"""
        if settings.ENABLE_AUDIT_LOGS:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                action_type=action_type,
                ip_address=ip_address,
                success=success,
                details=details
            )
            self.db.add(audit_log)
            await self.db.commit()
