from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import Settings

class Log(forms.Form):
    HOSTNAME = forms.CharField(widget=forms.TextInput(attrs={'id':'HOST_NAME'}), max_length=15, required=True)
    USERNAME = forms.CharField(widget=forms.TextInput(attrs={'id':'USER_NAME'}), max_length=15, required=True)
    PASSWORD = forms.CharField(widget=forms.PasswordInput(attrs={'id':'User_password',}), max_length=20, required=True)


class Send_MA(forms.Form):
    Sender=forms.EmailField(widget=forms.EmailInput(attrs={'id':'Sender'}),required=True)
    App_Password=forms.CharField(widget=forms.PasswordInput(attrs={'id':'SP'}),required=True)
    Recever=forms.EmailField(widget=forms.EmailInput(attrs={'id':'Recever'}),required=True)
    Massage=forms.CharField(label=" ",widget=forms.Textarea(attrs={'id':'Massage','cols':'150','rows':'13',}), max_length=500, required=True)


class AU(forms.Form):
    Username=forms.CharField(widget=forms.TextInput(attrs={'id':'Username'}),required=True)
    Password=forms.CharField(widget=forms.PasswordInput(attrs={'id':'Password'}), max_length=50,required=True)


class GPU(forms.Form):
    Password_Length = forms.IntegerField(label="Password Length",widget=forms.TextInput(attrs={'id':'Password_Length'}),required=True)
    Username_Length = forms.IntegerField(label="Username Length",widget=forms.TextInput(attrs={'id':'Username_Length'}),required=True)

class CPU(forms.Form):
    Password = forms.CharField(widget=forms.TextInput(attrs={'id':'Password'}),required=True)
    Username = forms.CharField(widget=forms.TextInput(attrs={'id':'Username'}),required=True)


class Ping(forms.Form):
    host = forms.CharField(widget=forms.TextInput(attrs={'id':'host'}),required=True)


class FDLBPI(forms.Form):
    Device_Public_ip_address = forms.GenericIPAddressField(widget=forms.TextInput(attrs={'id':'Device_Public_ip_address'}),required=True)

class TRA(forms.Form):
    host = forms.CharField(widget=forms.TextInput(attrs={'id':'Thost'}),required=True)

class PSK(forms.Form):
    TITLE = forms.CharField(max_length=100,widget=forms.TextInput(attrs={'id':'TEX'}), required=True)
    URLS = forms.URLField(max_length=100,widget=forms.TextInput(attrs={'id':'UR'}), required=True)
    USERNAME = forms.CharField(max_length=100,widget=forms.TextInput(attrs={'id':'U'}),required=True)
    PASSWORD = forms.CharField(max_length=100,widget=forms.PasswordInput(attrs={'id':'PASS'}),required=True)


class SettingsForm(forms.ModelForm):
    class Meta:
        model = Settings
        fields = [
            # Detection
            'Default_Report_path',
            'Ignore_Protection_Macs',
            'THRESHOLD',
            'Mac_Threshold',
            'Ip_Threshold',
            'Time_Window',
            'Brute_Force_Threshold',
            'Icmp_Threshold',
            'Request_Limit',
            # UI
            'theme_mode',
            'accent_color',
            'secondary_color',
            'bg_primary',
            'bg_card',
            'text_primary',
            'font_family',
            'font_size_base',
            'border_radius',
        ]
        widgets = {
            'Default_Report_path': forms.TextInput(attrs={
                'id': 'Default_Report_path',
                'placeholder': r'C:\Users\Public\Documents',
            }),
            'Ignore_Protection_Macs': forms.Textarea(attrs={
                'id': 'Ignore_Protection_Macs',
                'rows': 2,
                'placeholder': 'aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66',
            }),
            'THRESHOLD': forms.NumberInput(attrs={'id': 'THRESHOLD', 'min': 1}),
            'Mac_Threshold': forms.NumberInput(attrs={'id': 'Mac_Threshold', 'min': 1}),
            'Ip_Threshold': forms.NumberInput(attrs={'id': 'Ip_Threshold', 'min': 1}),
            'Time_Window': forms.NumberInput(attrs={'id': 'Time_Window', 'min': 5}),
            'Brute_Force_Threshold': forms.NumberInput(attrs={'id': 'Brute_Force_Threshold', 'min': 1}),
            'Icmp_Threshold': forms.NumberInput(attrs={'id': 'Icmp_Threshold', 'min': 1}),
            'Request_Limit': forms.NumberInput(attrs={'id': 'Request_Limit', 'min': 1}),
            'theme_mode': forms.Select(attrs={'id': 'theme_mode'}),
            'accent_color': forms.TextInput(attrs={'id': 'accent_color', 'type': 'color'}),
            'secondary_color': forms.TextInput(attrs={'id': 'secondary_color', 'type': 'color'}),
            'bg_primary': forms.TextInput(attrs={'id': 'bg_primary', 'type': 'color'}),
            'bg_card': forms.TextInput(attrs={'id': 'bg_card', 'type': 'color'}),
            'text_primary': forms.TextInput(attrs={'id': 'text_primary', 'type': 'color'}),
            'font_family': forms.Select(
                choices=[
                    ("'Inter', 'Segoe UI', system-ui, sans-serif", 'Inter / System'),
                    ("'Segoe UI', Tahoma, sans-serif", 'Segoe UI'),
                    ("'Roboto', sans-serif", 'Roboto'),
                    ("'JetBrains Mono', 'Fira Code', Consolas, monospace", 'Monospace (Code)'),
                    ("'Cairo', 'Segoe UI', sans-serif", 'Cairo (Arabic friendly)'),
                    ("Georgia, 'Times New Roman', serif", 'Serif'),
                ],
                attrs={'id': 'font_family'},
            ),
            'font_size_base': forms.NumberInput(attrs={'id': 'font_size_base', 'min': 12, 'max': 24}),
            'border_radius': forms.NumberInput(attrs={'id': 'border_radius', 'min': 0, 'max': 24}),
        }

    def clean_font_size_base(self):
        v = self.cleaned_data['font_size_base']
        if v < 12 or v > 24:
            raise forms.ValidationError('Font size must be between 12 and 24.')
        return v

    def clean_accent_color(self):
        return self._clean_hex('accent_color')

    def clean_secondary_color(self):
        return self._clean_hex('secondary_color')

    def clean_bg_primary(self):
        return self._clean_hex('bg_primary')

    def clean_bg_card(self):
        return self._clean_hex('bg_card')

    def clean_text_primary(self):
        return self._clean_hex('text_primary')

    def _clean_hex(self, field):
        v = (self.cleaned_data.get(field) or '').strip()
        if not v.startswith('#') or len(v) not in (4, 7):
            raise forms.ValidationError('Use a valid hex color like #00d4ff')
        return v