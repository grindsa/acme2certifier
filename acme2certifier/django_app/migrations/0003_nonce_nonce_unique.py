# Generated manually for atomic nonce consumption hardening

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("acme_srv", "0002_alter_housekeeping_value"),
    ]

    operations = [
        migrations.AlterField(
            model_name="nonce",
            name="nonce",
            field=models.CharField(max_length=50, unique=True),
        ),
    ]
