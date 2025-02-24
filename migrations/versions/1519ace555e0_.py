"""empty message

Revision ID: 1519ace555e0
Revises: 3b564cf8814b
Create Date: 2025-02-03 22:41:46.609022

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1519ace555e0'
down_revision = '3b564cf8814b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('comments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('expert_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['expert_id'], ['experts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ratings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('expert_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('rating', sa.Float(), nullable=False),
    sa.Column('review', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['expert_id'], ['experts.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('conversations', schema=None) as batch_op:
        batch_op.alter_column('project_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    with op.batch_alter_table('experts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rating_avg', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('total_reviews', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('success_rate', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('is_ai_free', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('experts', schema=None) as batch_op:
        batch_op.drop_column('is_ai_free')
        batch_op.drop_column('success_rate')
        batch_op.drop_column('total_reviews')
        batch_op.drop_column('rating_avg')

    with op.batch_alter_table('conversations', schema=None) as batch_op:
        batch_op.alter_column('project_id',
               existing_type=sa.INTEGER(),
               nullable=False)

    op.drop_table('ratings')
    op.drop_table('comments')
    # ### end Alembic commands ###
