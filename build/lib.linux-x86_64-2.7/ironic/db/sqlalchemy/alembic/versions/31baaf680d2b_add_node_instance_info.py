#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Add Node instance info

Revision ID: 31baaf680d2b
Revises: 3cb628139ea4
Create Date: 2014-03-05 21:09:32.372463

"""

# revision identifiers, used by Alembic.
revision = '31baaf680d2b'
down_revision = '3cb628139ea4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('nodes', sa.Column('instance_info',
                                     sa.Text(),
                                     nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('nodes', 'instance_info')
    ### end Alembic commands ###
