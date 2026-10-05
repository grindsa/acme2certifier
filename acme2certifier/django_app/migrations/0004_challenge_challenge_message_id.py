# Generated manually for email-reply-00 Message-ID persistence

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("acme_srv", "0003_nonce_nonce_unique"),
    ]

    operations = [
        migrations.AddField(
            model_name="challenge",
            name="challenge_message_id",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
