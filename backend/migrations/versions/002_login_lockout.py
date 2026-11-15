from alembic import op
import sqlalchemy as sa
revision = '002_login_lockout'
down_revision = '001_initial'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('login_failures', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))

def downgrade():
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'login_failures')
