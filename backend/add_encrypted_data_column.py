"""
Script para agregar la columna encrypted_data a la tabla messages
"""
import asyncio
from sqlalchemy import text
from app.core.database import engine

async def add_column():
    async with engine.begin() as conn:
        try:
            result = await conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'messages' AND column_name = 'encrypted_data'
            """))
            
            if result.fetchone():
                print("✅ La columna 'encrypted_data' ya existe")
            else:
                # Agregar la columna
                await conn.execute(text("""
                    ALTER TABLE messages 
                    ADD COLUMN encrypted_data TEXT
                """))
                print("✅ Columna 'encrypted_data' agregada exitosamente")
            
            # Verificar si encrypted_aes_key es nullable
            result = await conn.execute(text("""
                SELECT is_nullable 
                FROM information_schema.columns 
                WHERE table_name = 'messages' AND column_name = 'encrypted_aes_key'
            """))
            row = result.fetchone()
            if row and row[0] == 'NO':
                await conn.execute(text("""
                    ALTER TABLE messages 
                    ALTER COLUMN encrypted_aes_key DROP NOT NULL
                """))
                print("✅ Columna 'encrypted_aes_key' ahora es nullable")
            else:
                print("✅ Columna 'encrypted_aes_key' ya es nullable")
                
        except Exception as e:
            print(f"❌ Error: {e}")
            raise

if __name__ == "__main__":
    asyncio.run(add_column())
    print("\n✅ Migración completada")
