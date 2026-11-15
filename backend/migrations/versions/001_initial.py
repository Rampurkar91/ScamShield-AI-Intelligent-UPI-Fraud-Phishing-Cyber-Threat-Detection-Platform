from alembic import op
import sqlalchemy as sa
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('users', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('email', sa.String(254), nullable=False), sa.Column('password_hash', sa.String(255), nullable=False))
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_table('scans', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False), sa.Column('kind', sa.String(32), nullable=False), sa.Column('result', sa.JSON(), nullable=False), sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_scans_user_id', 'scans', ['user_id'])

def downgrade():
    op.drop_index('ix_scans_user_id', table_name='scans')
    op.drop_table('scans')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
