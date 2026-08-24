# Generated manually for Settings model
# بعد إضافة الموديل شغّل: python manage.py makemigrations NETWORK_MANGER
# أو انسخ هذا الملف إلى NETWORK_MANGER/migrations/ ثم: python manage.py migrate

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('NETWORK_MANGER', '0002_delete_sshcredential'),
    ]

    operations = [
        migrations.CreateModel(
            name='Settings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Default_Report_path', models.CharField(default='C:\\Users\\Public\\Documents', help_text='مسار حفظ تقارير PDF الافتراضي', max_length=500)),
                ('Ignore_Protection_Macs', models.TextField(blank=True, default='', help_text='عناوين MAC مفصولة بفواصل يتم تجاهلها')),
                ('THRESHOLD', models.PositiveIntegerField(default=1000, help_text='عتبة الحزم المشبوهة')),
                ('Mac_Threshold', models.PositiveIntegerField(default=100, help_text='عدد عناوين MAC الفريدة')),
                ('Ip_Threshold', models.PositiveIntegerField(default=1000, help_text='عتبة DoS / IP Flooding')),
                ('Time_Window', models.PositiveIntegerField(default=60, help_text='النافذة الزمنية بالثواني')),
                ('Brute_Force_Threshold', models.PositiveIntegerField(default=2, help_text='عدد محاولات الدخول الفاشلة')),
                ('Icmp_Threshold', models.PositiveIntegerField(default=100, help_text='عتبة ردود ICMP')),
                ('Request_Limit', models.PositiveIntegerField(default=1000, help_text='حد الطلبات العام')),
                ('theme_mode', models.CharField(choices=[('dark', 'Dark'), ('light', 'Light')], default='dark', max_length=10)),
                ('accent_color', models.CharField(default='#00d4ff', help_text='اللون الأساسي', max_length=7)),
                ('secondary_color', models.CharField(default='#00ff9f', help_text='اللون الثانوي', max_length=7)),
                ('bg_primary', models.CharField(default='#0a0e17', help_text='خلفية الصفحة', max_length=7)),
                ('bg_card', models.CharField(default='#1a2332', help_text='خلفية البطاقات', max_length=7)),
                ('text_primary', models.CharField(default='#e2e8f0', help_text='لون النص', max_length=7)),
                ('font_family', models.CharField(default="'Inter', 'Segoe UI', system-ui, sans-serif", help_text='عائلة الخط', max_length=80)),
                ('font_size_base', models.PositiveIntegerField(default=16, help_text='حجم الخط الأساسي')),
                ('border_radius', models.PositiveIntegerField(default=12, help_text='نصف قطر الحواف')),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('User', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='app_settings', to=settings.AUTH_USER_MODEL, verbose_name='User')),
            ],
            options={
                'verbose_name': 'App Setting',
                'verbose_name_plural': 'App Settings',
            },
        ),
    ]
