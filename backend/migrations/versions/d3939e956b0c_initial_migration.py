"""initial_migration

Revision ID: d3939e956b0c
Revises: 
Create Date: 2025-06-24 17:12:53.423772

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'd3939e956b0c'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('captura', sa.Column('usuario_id', sa.Integer(), nullable=False))
    op.add_column('captura', sa.Column('remitente', sa.String(length=100), nullable=True))
    op.add_column('captura', sa.Column('atendio', sa.String(length=50), nullable=True))
    op.add_column('captura', sa.Column('pdf_url', sa.String(length=200), nullable=True))
    op.add_column('captura', sa.Column('eliminado', sa.Boolean(), nullable=True))
    op.add_column('captura', sa.Column('eliminado_por', sa.Integer(), nullable=True))
    op.add_column('captura', sa.Column('tipo', sa.String(length=50), nullable=False))
    op.add_column('captura', sa.Column('status', sa.String(length=50), nullable=True))
    op.add_column('captura', sa.Column('respuesta_pdf_url', sa.String(length=200), nullable=True))
    op.add_column('captura', sa.Column('completado', sa.Boolean(), nullable=True))
    op.drop_constraint(op.f('fk_remitente_id'), 'captura', type_='foreignkey')
    op.create_foreign_key(None, 'captura', 'usuarios', ['usuario_id'], ['id'])
    op.create_foreign_key(None, 'captura', 'usuarios', ['eliminado_por'], ['id'])
    op.drop_column('captura', 'remitente_id')
    op.alter_column('directorio_interno', 'cargo',
               existing_type=mysql.VARCHAR(length=250),
               nullable=True)
    op.drop_index(op.f('nombre'), table_name='directorio_interno')
    op.alter_column('usuarios', 'usuario',
               existing_type=mysql.VARCHAR(length=250),
               nullable=False)
    op.alter_column('usuarios', 'contrasena',
               existing_type=mysql.VARCHAR(length=250),
               nullable=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('usuarios', 'contrasena',
               existing_type=mysql.VARCHAR(length=250),
               nullable=True)
    op.alter_column('usuarios', 'usuario',
               existing_type=mysql.VARCHAR(length=250),
               nullable=True)
    op.create_index(op.f('nombre'), 'directorio_interno', ['nombre'], unique=True)
    op.alter_column('directorio_interno', 'cargo',
               existing_type=mysql.VARCHAR(length=250),
               nullable=False)
    op.add_column('captura', sa.Column('remitente_id', mysql.INTEGER(), autoincrement=False, nullable=True))
    op.drop_constraint(None, 'captura', type_='foreignkey')
    op.drop_constraint(None, 'captura', type_='foreignkey')
    op.create_foreign_key(op.f('fk_remitente_id'), 'captura', 'directorio_interno', ['remitente_id'], ['id'])
    op.drop_column('captura', 'completado')
    op.drop_column('captura', 'respuesta_pdf_url')
    op.drop_column('captura', 'status')
    op.drop_column('captura', 'tipo')
    op.drop_column('captura', 'eliminado_por')
    op.drop_column('captura', 'eliminado')
    op.drop_column('captura', 'pdf_url')
    op.drop_column('captura', 'atendio')
    op.drop_column('captura', 'remitente')
    op.drop_column('captura', 'usuario_id')
    # ### end Alembic commands ###
