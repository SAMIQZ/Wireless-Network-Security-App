from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import User
from .fields import EncryptedCharField
# Create your models here.

class NET(models.Model) :
    FNAME=models.CharField(max_length=50)
    USER=models.ForeignKey(User, on_delete=models.CASCADE,blank=True, null=True)
    Msg = models.TextField(max_length=300,null=True,blank=True)
    MsgDate = models.DateField(auto_now=True)
    MsgTime = models.TimeField(auto_now=True)
    MsgId= models.CharField(blank=True, null=True,max_length=100)

class PK(models.Model):
    USER =  models.ForeignKey(User, on_delete=models.CASCADE,blank=True, null=True)
    TITLE = models.CharField(max_length=100,null=True,blank=True)
    URLS = models.URLField(blank=True, null=True,max_length=200)
    USERNAME = models.CharField(max_length=100,null=True,blank=True)
    PASSWORD = models.CharField(max_length=100,null=True,blank=True)
    PKId= models.CharField(blank=True, null=True,max_length=100)

class Device(models.Model):
    ip_address = models.GenericIPAddressField( protocol="both", unpack_ipv4=False)
    mac_address = models.CharField(max_length=17)
    hostname = models.CharField(max_length=255, blank=True)
    os = models.CharField(max_length=255, blank=True)


class FailLogin(models.Model):
    User = models.CharField(max_length=50,blank=True, null=True)
    Fail = models.IntegerField(default=0)
    Date = models.DateTimeField(auto_now_add=True)

class Settings(models.Model):

    User = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='app_settings',
        verbose_name='User',
    )

    Default_Report_path = models.CharField(
        max_length=500,
        default=r'C:\Users\Public\Documents',
        help_text='Default PDF Path',
    )
    Ignore_Protection_Macs = models.TextField(
        blank=True,
        default='',
        help_text='example aa:bb:cc:dd:ee:ff,11:22:33:44:55:66',
    )
    THRESHOLD = models.PositiveIntegerField(
        default=1000,
        help_text='(TCP SYN / suspicious traffic)',
    )
    Mac_Threshold = models.PositiveIntegerField(
        default=100,
        help_text='عدد عناوين MAC الفريدة خلال النافذة الزمنية لاكتشاف MAC Flooding',
    )
    Ip_Threshold = models.PositiveIntegerField(
        default=1000,
        help_text='عتبة اكتشاف DoS / IP Flooding',
    )
    Time_Window = models.PositiveIntegerField(
        default=60,
        help_text='النافذة الزمنية بالثواني لحساب الفيضانات',
    )
    Brute_Force_Threshold = models.PositiveIntegerField(
        default=2,
        help_text='عدد محاولات الدخول الفاشلة قبل التنبيه',
    )
    Icmp_Threshold = models.PositiveIntegerField(
        default=100,
        help_text='عتبة ردود ICMP غير الطبيعية (Deauth / Ping flood)',
    )
    Request_Limit = models.PositiveIntegerField(
        default=1000,
        help_text='حد الطلبات العام',
    )

    theme_mode = models.CharField(
        max_length=10,
        choices=[('dark', 'Dark'), ('light', 'Light')],
        default='dark',
    )
    accent_color = models.CharField(
        max_length=7,
        default='#00d4ff',
        help_text='اللون الأساسي (Cyan) بصيغة #RRGGBB',
    )
    secondary_color = models.CharField(
        max_length=7,
        default='#00ff9f',
        help_text='اللون الثانوي (Green)',
    )
    bg_primary = models.CharField(
        max_length=7,
        default='#0a0e17',
        help_text='خلفية الصفحة الرئيسية',
    )
    bg_card = models.CharField(
        max_length=7,
        default='#1a2332',
        help_text='خلفية البطاقات',
    )
    text_primary = models.CharField(
        max_length=7,
        default='#e2e8f0',
        help_text='لون النص الأساسي',
    )
    font_family = models.CharField(
        max_length=80,
        default="'Inter', 'Segoe UI', system-ui, sans-serif",
        help_text='عائلة الخط الرئيسية',
    )
    font_size_base = models.PositiveIntegerField(
        default=16,
        help_text='حجم الخط الأساسي بالبكسل (12–24)',
    )
    border_radius = models.PositiveIntegerField(
        default=12,
        help_text='نصف قطر الحواف (px)',
    )

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'App Setting'
        verbose_name_plural = 'App Settings'

    def __str__(self):
        return f'Settings for {self.User.username}'

    def known_macs_set(self):
        macs = set()
        for part in (self.Ignore_Protection_Macs or '').split(','):
            m = part.strip().lower()
            if m:
                macs.add(m)
        return macs

    @classmethod
    def get_or_create_for_user(cls, user):
        obj, _ = cls.objects.get_or_create(User=user)
        return obj