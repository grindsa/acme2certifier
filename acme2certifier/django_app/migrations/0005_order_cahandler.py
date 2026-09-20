# Generated manually for multi-CAhandler order persistence

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("acme_srv", "0004_challenge_challenge_message_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="order",
            name="cahandler",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
    ]
