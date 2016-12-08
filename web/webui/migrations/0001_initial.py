# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='status_machine',
            fields=[
                ('id', models.AutoField(auto_created=True, serialize=False, primary_key=True, verbose_name='ID')),
                ('machine_text', models.CharField(max_length=200)),
                ('date_update', models.DateTimeField(verbose_name='date update')),
            ],
        ),
    ]
