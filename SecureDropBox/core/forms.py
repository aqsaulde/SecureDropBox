# forms.py
from django import forms
from .models import Keys
from .models import FileModel
from .models import EncryptionFiles

class KeyGenerationForm(forms.Form):
    KEY_SIZES = [
        ("Select key size", "Select key size"),  # Default text
        (2048, '2048 bits'),
        (4096, '4096 bits'),
    ]
    key_size = forms.ChoiceField(choices=KEY_SIZES, initial=2048,widget=forms.Select(attrs={
            'class': 'form-control select-input'
        }))
    key_name = forms.CharField(label="Key name",widget=forms.TextInput(attrs={
            'class': 'form-control text-input',
            'placeholder': 'Enter key name'
        }))

class DecryptForm(forms.Form):
    key = forms.FileField(label="Upload Decryption Key",widget=forms.ClearableFileInput(attrs={
            'class': 'form-control file-input'
        }))
    selected_file = forms.FileField(label="File to Decrypt",widget=forms.ClearableFileInput(attrs={
            'class': 'form-control file-input'
        }))

class EncryptForm(forms.Form):
    key = forms.ModelChoiceField(queryset=Keys.objects.all(), label="Select Encryption Key", widget=forms.Select(attrs={
            'class': 'form-control',  # Bootstrap example
        }))
    existing_file = forms.ModelChoiceField(
        queryset=FileModel.objects.all(),
        required=False,
        label="Choose a file to Encrypt from server",
        widget=forms.Select(attrs={
            'class': 'form-control',  # Bootstrap example
        })
    )
    upload_file = forms.FileField(
        required=False,
        label="Or upload a new file (Supported Type : CSV,JSON,TXT,DOCX,XML)",
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control file-input'
        })
    )
    def __init__(self, *args, file_choices=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['key'].label_from_instance = lambda obj: f" RSA Key from (User: {obj.user.username}) with UID - {obj.key_id} and Key Name - {obj.key_name}"
    
        
