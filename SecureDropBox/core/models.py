# Create your models here.
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import models
import uuid

class FileModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/')
    filesize = models.FloatField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    shared = models.BooleanField(default=False)
    share_token = models.CharField(max_length=100, blank=True, null=True)
    expiry_time = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.filename
    
    def is_expired(self):
        return self.expiry_time and timezone.now() > self.expiry_time
    
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_image = models.ImageField(upload_to='profile_pics/', default='default.jpg')
    bio = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.user.username
      
class Keys(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,unique=False)
    key_id = models.CharField(max_length=20, primary_key=True)
    key_name = models.CharField(max_length=100, blank=False)
    key_type = models.TextField()  
    key_size = models.IntegerField(default=2048)
    public_key = models.TextField()
    private_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    def save(self, *args, **kwargs):
        if not self.key_id:
            self.key_id = f"UID{uuid.uuid4().hex[:6].upper()}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"RSA Keys for {self.user.username} ({self.key_size} bits)"
    
class EncryptionFiles(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,unique=False)
    e_id = models.CharField(max_length=20, primary_key=True)
    file_name = models.CharField(max_length=255)
    file_extension = models.CharField(max_length=5)  
    file = models.FileField(upload_to='encrypted_uploads/')
    filesize = models.FloatField()
    private_key = models.ForeignKey(Keys,on_delete=models.CASCADE,null=True, blank=True)
    shared_with = models.JSONField(default=list)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def save(self, *args, **kwargs):
        if not self.e_id:
            self.e_id = f"FEUID{uuid.uuid4().hex[:8].upper()}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.file_name
    
class DecryptionFiles(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,unique=False)
    d_id = models.CharField(max_length=20, primary_key=True)
    file_name = models.CharField(max_length=255)
    file_extension = models.CharField(max_length=5)  
    file = models.FileField(upload_to='decrypted_uploads/')
    filesize = models.FloatField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def save(self, *args, **kwargs):
        if not self.d_id:
            self.d_id = f"FDUID{uuid.uuid4().hex[:8].upper()}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.file_name

class PublicFileShare(models.Model):
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    key = models.ForeignKey(Keys,on_delete=models.CASCADE,null=True, blank=True)
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=True, blank=True)
    file = models.ForeignKey(EncryptionFiles,on_delete=models.CASCADE,null=True, blank=True)
    file_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    def is_expired(self):
        return timezone.now() > self.expires_at