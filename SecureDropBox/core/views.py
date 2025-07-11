from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.views.decorators.http import require_POST
from django.core.mail import EmailMessage
from django.contrib import messages
from django.core.mail import send_mail
from .forms import KeyGenerationForm
from .utils import generate_key_pair
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import shutil
import tempfile
import base64
import magic
from .models import FileModel
from .models import EncryptionFiles
from .models import DecryptionFiles
from .models import PublicFileShare
from .models import Keys
from django.conf import settings
from core.encryption import encrypt_file
from .encryption import decrypt_file 
from django.utils import timezone
from datetime import timedelta
from .models import Profile
from .models import EncryptionFiles
from .models import DecryptionFiles
from .forms import DecryptForm
from .forms import EncryptForm
import uuid
import os

def home_view(request):
    return render(request, 'core/home.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            next_url = request.POST.get('next') or request.GET.get('next')
            return redirect(next_url or '/dashboard')
        else:
            # handle error
            pass
    return render(request, 'core/login.html')

def register_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        email = request.POST['email']

        if password1 != password2:
            messages.error(request, 'Password and confirm password doesnot match')

        elif User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
        else:
            user = User.objects.create_user(username=username, password=password1, email=email, is_active=False)

            current_site = get_current_site(request)
            subject = 'Activate Your SecureDropBox Account'
            message = render_to_string('core/email_verification.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token_generator.make_token(user),
            })

            send_mail(subject, message, 'no-reply@securedropbox.com', [email], fail_silently=False)
            messages.success(request, 'Account created! Check your email to verify.')
            return redirect('/login')
    return render(request, 'core/register.html')

def about_view(request):
    return render(request, 'core/about.html')

def contact_view(request):
    return render(request, 'core/contact.html')

def learn_view(request):
    return render(request, 'core/learn.html')

def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except Exception as e:
        user = None

    if user and token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Account activated! You can now log in.')
        return redirect('login')
    else:
        messages.error(request, 'Activation link is invalid or expired.')
        return redirect('register')
    
@login_required
def dashboard_view(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        user = request.user
        mime = magic.from_buffer(uploaded_file.read(2048), mime=True)
        uploaded_file.seek(0)
        allowed_mimes = [
            'text/csv',
            'text/plain',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
            'application/json',
            'application/xml',  # sometimes 'text/xml'
            'text/xml',
        ]
        if mime not in allowed_mimes:
            messages.error(request, "Please upload a valid file (Supported Type : CSV,JSON,TXT,DOCX,XML)")
            return redirect('/dashboard')
        # Save original file temporarily
        original_path = os.path.join(settings.MEDIA_ROOT, 'temp\\', uploaded_file.name)
        os.makedirs(os.path.dirname(original_path), exist_ok=True)

        with open(original_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)

        # Encrypt the file
        upload_path = os.path.join(settings.MEDIA_ROOT, 'uploads\\', f'{uploaded_file.name}')
        os.makedirs(os.path.dirname(upload_path), exist_ok=True)
        shutil.move(original_path, upload_path)
        # os.remove(original_path)  # Delete original temp file

        # Save to DB
        FileModel.objects.create(
            user=user,
            filename=uploaded_file.name,
            file=f'uploads/{uploaded_file.name}',
            filesize=round(uploaded_file.size / 1024, 2),
        )
        messages.success(request, 'File Uploaded Successfully')
        return redirect('dashboard')
    decryption_files = DecryptionFiles.objects.filter(user=request.user).order_by('-created_at')
    encryption_files = EncryptionFiles.objects.filter(user=request.user).order_by('-created_at')
    files = FileModel.objects.filter(user=request.user)
    return render(request, 'core/dashboard.html', {'files': files,'encryption_files':encryption_files,'decryption_files':decryption_files})

def access_shared_file(request, token):
    try:
        file_obj = FileModel.objects.get(share_token=token, shared=True)
        if file_obj.is_expired():
            return HttpResponseForbidden("This file link has expired.")
        # Provide access to the file or download
        return render(request, 'core/view_shared_file.html', {'file': file_obj})
    except FileModel.DoesNotExist:
        return HttpResponseForbidden("Invalid share link.")

def logout_view(request):
    logout(request)
    return redirect('/user_login')

@login_required
def download_file(request, file_id):
    try:
        file_obj = FileModel.objects.get(id=file_id, user=request.user)
    except FileModel.DoesNotExist:
        raise Http404("File not found or you do not have permission.")

    encrypted_path = os.path.join(settings.MEDIA_ROOT, str(file_obj.file))
    decrypted_path = os.path.join(settings.MEDIA_ROOT, 'decrypted', file_obj.filename)

    # Make sure the 'decrypted' folder exists
    os.makedirs(os.path.dirname(decrypted_path), exist_ok=True)

    # Decrypt the file
    decrypt_file(encrypted_path, decrypted_path)

    # Return as downloadable response
    return FileResponse(open(decrypted_path, 'rb'), as_attachment=True, filename=file_obj.filename)

@login_required
def delete_file(request, file_id):
    file_obj = get_object_or_404(FileModel, id=file_id, user=request.user)
    file_obj.file.delete()  # Deletes the file from MEDIA folder
    file_obj.delete()       # Deletes the DB entry
    messages.success(request, "File deleted successfully.")
    return redirect('dashboard')

@login_required
def settings_view(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')

        # Update user basic info
        user = request.user
        user.first_name = full_name.split()[0]
        user.last_name = " ".join(full_name.split()[1:]) if len(full_name.split()) > 1 else ""
        user.email = email
        user.save()

        # Update profile image
        profile, created = Profile.objects.get_or_create(user=user)
        if 'profile_image' in request.FILES:
            profile.profile_image = request.FILES['profile_image']
            profile.save()

        return redirect('settings')

    return render(request, 'core/settings.html')

@login_required
def share_file(request, file_id):
    # Always define file_obj at the start
    file_obj = get_object_or_404(FileModel, id=file_id, user=request.user)

    if request.method == 'POST':
        file_obj.shared = True
        file_obj.share_token = str(uuid.uuid4())

        expiry_hours = int(request.POST.get('expiry_hours', 1))  # default 1 hour
        file_obj.expiry_time = timezone.now() + timedelta(hours=expiry_hours)

        file_obj.save()
        return redirect('dashboard')

        # Send email with download link
        send_mail(
            subject="You've received a secure file",
            message=f"You can download the file here: {download_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
        )

        messages.success(request, "File shared successfully.")
        return redirect('dashboard')

    return render(request, 'core/share_file.html', {'file': file_obj})

@login_required
def generate_keys(request):
    all_keys=Keys.objects.all().order_by('-created_at')
    private_key = public_key = None
    if request.method == 'POST':
        form = KeyGenerationForm(request.POST)
        if form.is_valid():
            passphrase = request.user.username + "_secure"
            key_size = int(form.cleaned_data['key_size'])
            key_name = str(form.cleaned_data['key_name'])
            private_key, public_key = generate_key_pair(key_size, passphrase)
            key_pair = Keys.objects.create(
                user=request.user,
                key_type='RSA',
                key_name=key_name,
                key_size=key_size,
                private_key=private_key,
                public_key=public_key
            )
            messages.success(request, 'Key Created successfully.')
            return redirect('/generate-keys/')
            
    else:
        form = KeyGenerationForm()
    
    return render(request, 'core/generate_keys_view.html', {
        'form': form,
        'keys': all_keys,
    })

@login_required
def download_key(request, key_id, key_type='private'):
    try:
        key_pair = Keys.objects.get(key_id=key_id, user=request.user)
    except Keys.DoesNotExist:
        messages.error(request, ' Key Not Found')

    if key_type == "private":
        content = key_pair.private_key
        filename = f"private_key_{key_id}.pem"
    elif key_type == "public":
        content = key_pair.public_key
        filename = f"public_key_{key_id}.pem"
    else:
        messages.error(request, 'Invalid Key Type.')

    response = HttpResponse(content, content_type='application/x-pem-file')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

@login_required
def delete_key(request, key_id):
    if request.method == 'POST':
        key_pair = Keys.objects.get(key_id=key_id, user=request.user)
        key_pair.delete()
        messages.success(request, 'Key deleted successfully.')
        return redirect('/generate-keys/')  # Or wherever you want to redirect after deletion
    return redirect('/generate-keys/')

@require_POST
@login_required
def share_private_key(request):
    key_id = request.POST.get('key_id')
    email = request.POST.get('email')

    if not key_id or not email:
        messages.error(request, "Missing key ID or email.")
        return redirect('/generate-keys/')

    key_pair = get_object_or_404(Keys, key_id=key_id, user=request.user)
    
    # Prepare the attachment
    pem_content = key_pair.private_key.encode('utf-8')  # Ensure it's bytes
    attachment_name = f"private_key_{key_id}.pem"

    # Prepare and send email
    email_msg = EmailMessage(
        subject='Your Private RSA Key',
        body='Attached is your requested private RSA key.',
        from_email='noreply@yourdomain.com',
        to=[email],
    )
    email_msg.attach(attachment_name, pem_content, 'application/x-pem-file')
    email_msg.send()

    messages.success(request, f"Private key sent to {email}.")
    return redirect('/generate-keys/')

@login_required
def encrypt_view(request):
    file_choices = EncryptionFiles.objects.all().order_by('-created_at')
    if request.method == 'POST':
        form = EncryptForm(request.POST, request.FILES,file_choices=file_choices)
        if form.is_valid():
            key = form.cleaned_data['key']

            selected_file = form.cleaned_data.get('existing_file')
            uploaded_file = form.cleaned_data.get('upload_file')
            if not selected_file and not uploaded_file:
                messages.error(request, "Please select a existing file or upload one.")
                return redirect('/encryption')  # replace with your actual view name

            if selected_file and uploaded_file:
                messages.error(request, "Select either a existing file or upload one, not both.")
                return redirect('/encryption')
            
            
            # Handle valid input
            if uploaded_file:
                mime = magic.from_buffer(uploaded_file.read(2048), mime=True)
                uploaded_file.seek(0)
                allowed_mimes = [
                    'text/csv',
                    'text/plain',
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
                    'application/json',
                    'application/xml',  # sometimes 'text/xml'
                    'text/xml',
                ]
                if mime not in allowed_mimes:
                    messages.error(request, "Please upload a valid file (Supported Type : CSV,JSON,TXT,DOCX,XML)")
                    return redirect('/encryption')
                with tempfile.NamedTemporaryFile(mode='wb+', delete=False) as temp_file:
                    for chunk in uploaded_file.chunks():
                        temp_file.write(chunk)
                selected_file = temp_file.name  # Save path if needed
                name, extension = os.path.splitext(uploaded_file.name)
                file_path = selected_file
            else:
                file_path = os.path.join(settings.MEDIA_ROOT, 'uploads\\'+selected_file.filename)
                # return redirect('encryption/')
                name, extension = os.path.splitext(selected_file.filename)
            symmetric_key = secrets.token_bytes(32)
            # Generate a random 16-byte IV for AES
            iv = secrets.token_bytes(16)
            symmetric_key_b64 = base64.b64encode(symmetric_key).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            file_credentials = f"{symmetric_key_b64}::{iv_b64}".encode('utf-8')
            public_key_pem = key.public_key.encode('utf-8')
            # Load it as an RSA public key object
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            encrypted_key = public_key.encrypt(
                    file_credentials,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # Optionally encode to base64 to make it text-safe
            encoded_key = base64.b64encode(encrypted_key).decode('utf-8')
            # Create a temp file
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp\\')
            os.makedirs(temp_dir, exist_ok=True)
            temp_file_empty = tempfile.NamedTemporaryFile(mode='wb', dir=temp_dir, delete=False, suffix=".enc")
            # Write the encrypted key as the first line
            temp_file_empty.write(encoded_key.encode('utf-8') + b'\n')
            # Create AES cipher in CBC mode
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()
            with open(file_path, 'rb') as infile:
                while chunk := infile.read(4096):
                    if len(chunk) < 4096:
                        # Add padding only to the final chunk
                        chunk = padder.update(chunk) + padder.finalize()
                    else:
                        chunk = padder.update(chunk)

                    encrypted_chunk = encryptor.update(chunk)
                    temp_file_empty.write(encrypted_chunk) 
            # Finalize and write any remaining encrypted data
            temp_file_empty.write(encryptor.finalize())
            temp_file_empty.flush()
            temp_file_empty.close()
            size_bytes = os.path.getsize(temp_file_empty.name)
            target_directory = os.path.join(settings.MEDIA_ROOT, 'encrypted_uploads\\')
            target_filename = f'enc_{name}{extension}.enc'
            os.makedirs(target_directory, exist_ok=True)
            new_path = os.path.join(target_directory, target_filename)
            shutil.move(temp_file_empty.name, new_path)
            # TODO: add your encrypted logic here using key.private_key and encrypted_file
            EncryptionFiles.objects.create(
                file_name=f'enc_{name}{extension}.enc',
                file_extension=extension,
                private_key = key,
                user = request.user,
                file=f'encrypted_uploads/enc_{name}{extension}.enc',
                filesize=round(size_bytes/ 1024, 2),
                shared_with = [] 
            )
            messages.success(request, "File Encrypted successfully!")
            return redirect('/dashboard')
            # return or send decrypted file as response
        else:
            messages.error(request,form.errors)
            return redirect('/encryption')
    else:
        form = EncryptForm(file_choices=file_choices)

    return render(request, 'core/encryption.html', {'form': form})

@login_required
def decrypt_view(request):
    if request.method == 'POST':
        form = DecryptForm(request.POST, request.FILES)
        if form.is_valid():
            # 
            valid_extensions = ['.enc']
            key = request.FILES['key']
            selected_file = request.FILES['selected_file']
            filename = selected_file.name.lower()
            file_data = selected_file.read()
            passphrase = request.user.username + "_secure"
            if not key.name.endswith('.pem'):
                messages.error(request, "Invalid file type. Please upload a  valid key .pem file.")
                return redirect('/decryption') 
            if not any(filename.endswith(ext) for ext in valid_extensions):
                messages.error(request, "Invalid file type. Please upload a valid .enc file to decrypt")
                return redirect('/decryption')
            try:
                private_key = serialization.load_pem_private_key(
                    key.read(),
                    password=passphrase.encode(),
                    backend=default_backend())
            except:
                messages.error(request, "Error Loading Private Key")
                return redirect('/decryption') 
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in selected_file.chunks():  # Efficiently handle large files
                    temp_file.write(chunk)
                temp_file_path = temp_file.name
            with open(temp_file_path, 'rb') as file:
                first_line = file.readline().strip()
            base_encoded = base64.b64decode(first_line)
            try:
                decrypted_key = private_key.decrypt(
                    base_encoded,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except:
                messages.error(request, "Error Decrypting Private Key")
                return redirect('/decryption')  
            symmetric_key,iv = decrypted_key.decode().split("::")
            symmetric_key = base64.b64decode(symmetric_key)
            iv = base64.b64decode(iv)
            decrypted_data=b''
            # TODO: add your decryption logic here using key.private_key and encrypted_file
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            try:
                with open(temp_file_path, 'rb') as f:
                    f.readline()
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        decrypted_data+= decryptor.update(chunk)
                decrypted_data += decryptor.finalize()
                # Now unpad the result using PKCS7
                unpadder = sym_padding.PKCS7(128).unpadder()
                decrypted_data_final = unpadder.update(decrypted_data) + unpadder.finalize()
                target_directory = os.path.join(settings.MEDIA_ROOT, 'decrypted_uploads\\')
                target_filename = f'dec_{selected_file.name.split(".enc")[0]}'
                os.makedirs(target_directory, exist_ok=True)
                new_path = os.path.join(target_directory, target_filename)
                with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
                    # Write data to the file
                    temp_file.write(decrypted_data_final)
                size_bytes = os.path.getsize(temp_file.name)
                shutil.move(temp_file.name, new_path)
                target_filename.split("enc_")[1]
                extension =target_filename.split(".")[1]
                DecryptionFiles.objects.create(
                    file_name=f'{target_filename}',
                    file_extension=extension,
                    user = request.user,
                    file=f'decrypted_uploads/{target_filename}',
                    filesize=round(size_bytes/ 1024, 2), 
                )
                messages.success(request, "File decrypted successfully! Saved to decrypted files")
                return redirect('/dashboard') 
            except:
                messages.error(request, "Error Decrypting File")
                return redirect('/decryption')      
            # return or send decrypted file as response
        else:
            messages.error(request,form.errors)
            return redirect('/decryption')
    else:
        form = DecryptForm()

    return render(request, 'core/decryption.html', {'form': form})

@login_required
def download_encrypted_file(request, file_id):
    try:
        file_obj = EncryptionFiles.objects.get(e_id=file_id, user=request.user)
    except FileModel.DoesNotExist:
        messages.error(request,'File Not Found')
        return redirect('dashboard/')

    encrypted_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_uploads\\'+file_obj.file_name)

    # Return as downloadable response
    return FileResponse(open(encrypted_path, 'rb'), as_attachment=True, filename=file_obj.file_name)

@login_required
def delete_encrypted_file(request,file_id):
    file_obj = get_object_or_404(EncryptionFiles, e_id=file_id, user=request.user)
    file_obj.file.delete()  # Deletes the file from MEDIA folder
    file_obj.delete()       # Deletes the DB entry
    messages.success(request, "File deleted successfully.")
    return redirect('dashboard')

@login_required
def download_decrypted_file(request, file_id):
    try:
        file_obj = DecryptionFiles.objects.get(d_id=file_id, user=request.user)
    except FileModel.DoesNotExist:
        messages.error(request,'File Not Found')
        return redirect('/dashboard')

    encrypted_path = os.path.join(settings.MEDIA_ROOT, 'decrypted_uploads\\'+file_obj.file_name)

    # Return as downloadable response
    return FileResponse(open(encrypted_path, 'rb'), as_attachment=True, filename=file_obj.file_name)

@login_required
def delete_decrypted_file(request,file_id):
    file_obj = get_object_or_404(DecryptionFiles, d_id=file_id, user=request.user)
    file_obj.file.delete()  # Deletes the file from MEDIA folder
    file_obj.delete()       # Deletes the DB entry
    messages.success(request, "File deleted successfully.")
    return redirect('/dashboard')

@login_required
def share_encrypted_file(request):
    if request.method == 'POST':
        file_name = request.POST.get('file_name')
        file_size_kb = int(request.POST.get('file_size', 0))
        share_option = request.POST.get('share_option')
        file_id = request.POST.get('file_id')
        email = request.POST.get('email', '').strip()

        file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_uploads\\', file_name)
        file_size_limit_kb = 10 * 1024  # 10MB
        Files = get_object_or_404(EncryptionFiles, e_id=file_id, user=request.user)
        if share_option == 'email':
            if not email:
                messages.error(request, "Recipient email is required.")
                return redirect('/dashboard')
            if file_size_kb > file_size_limit_kb:
                messages.error(request, "File exceeds 10MB. Cannot be sent via email.")
                return redirect('/dashboard')
            
            if not os.path.exists(file_path):
                messages.error(request, "File not found.")
                return redirect('/dashboard')
            
            # Prepare the attachment
            pem_content = Files.private_key.private_key  # Ensure it's bytes
            attachment_name = f"private_key_{Files.private_key.key_id}.pem"
            try:
                mail = EmailMessage(
                    subject=f'{request.user} has Shared Files with You',
                    body='Attached is your requested private RSA key and Encrypted File',
                    from_email='noreply@yourdomain.com',
                    to=[email]
                )
                mail.attach(attachment_name, pem_content, 'application/x-pem-file')
                mail.attach_file(file_path)
                mail.send()
                messages.success(request, " File has been emailed successfully.")
            except Exception as e:
                messages.error(request, f"Failed to send email: {str(e)}")

            return redirect('/dashboard')
        if share_option == 'public':
            expires = timezone.now() + timezone.timedelta(hours=1)
            public_link = PublicFileShare.objects.create(
                file_name=file_name,
                expires_at=expires,
                key = Files.private_key,
                user = request.user,
                file = Files
            )
            download_url = request.build_absolute_uri(f'/public/decrypt/download/{public_link.token}/')
            try:
                send_mail(
                    subject='Here is your public download link',
                    message=f'The file "{file_name}" has been shared with you.\n\n'
                            f'You can download it using the link below (valid for 24 hours):\n\n{download_url}',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                messages.success(request, " Public link sent to recipient via email.")
            except Exception as e:
                messages.error(request, f" Failed to send email")
            return redirect('/dashboard')
        
def public_file_download_view(request,token):
    error_message = ''
    try:
        share = PublicFileShare.objects.get(token=token)
        if share.is_expired():
            error_message = 'Link has expired. Please request another one.'
    except PublicFileShare.DoesNotExist:
        share = None
        error_message = 'Link Not Found'
    
    # file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_uploads\\', share.file_name)
    # if not os.path.exists(file_path):
    #     messages.error(request, f"File not found")

    return  render(request, 'core/public_decrypt.html', {
        'share': share,
        'error_message' : error_message
    })

def public_file_download(request,token):
    share_obj =PublicFileShare.objects.get(token=token)
    #Load the private key
    passphrase = share_obj.user.username + "_secure"
    private_key = serialization.load_pem_private_key(
        share_obj.key.private_key.encode(),
        password=passphrase.encode(),
        backend=default_backend())
    target_directory = os.path.join(settings.MEDIA_ROOT, 'encrypted_uploads\\'+share_obj.file_name)
    with open(target_directory, 'rb') as source_file, tempfile.NamedTemporaryFile(delete=False) as dest_file:
        for chunk in iter(lambda: source_file.read(4096), b''):
            dest_file.write(chunk)
        temp_file_path = dest_file.name
    with open(temp_file_path, 'rb') as file:
        first_line = file.readline().strip()
    base_encoded = base64.b64decode(first_line)
    try:
        decrypted_key = private_key.decrypt(
            base_encoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        messages.error(request, "Error Decrypting Private Key")
        return redirect(request.referrer)

    symmetric_key,iv = decrypted_key.decode().split("::")
    symmetric_key = base64.b64decode(symmetric_key)
    iv = base64.b64decode(iv)
    decrypted_data=b''
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        with open(temp_file_path, 'rb') as f:
            f.readline()
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                decrypted_data+= decryptor.update(chunk)
        decrypted_data += decryptor.finalize()
        # Now unpad the result using PKCS7
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted_data_final = unpadder.update(decrypted_data) + unpadder.finalize()
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
            # Write data to the file
            temp_file.write(decrypted_data_final)
        target_filename = share_obj.file_name.split(".enc")[0]
        download_as = f'{target_filename.split("enc_")[1]}'
    except:
        messages.error(request, "Error Decrypting File")
        return redirect(request.referrer)
    
    # os.rename(temp_file_path, download_as)
    # full_path = os.path.join(temp_file, download_as)
    return FileResponse(open(temp_file.name, 'rb'), as_attachment=True, filename=download_as)
    