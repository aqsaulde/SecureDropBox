from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.home_view, name='home'),
    path('user_login/', views.user_login, name='user_login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('share/<int:file_id>/', views.share_file, name='share_file'),
    path('shared/<str:token>/', views.access_shared_file, name='access_shared_file'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
    path('about/', views.about_view, name='about'),
    path('contact/', views.contact_view, name='contact'),
    path('settings/', views.settings_view, name='settings'),
    path('learn/', views.learn_view, name='learn'),
    path('generate-keys/', views.generate_keys, name='generate_keys'),
    path('download_key/<str:key_id>/<str:key_type>/', views.download_key, name='download_key'),
    path('keys/delete/<str:key_id>/', views.delete_key, name='delete_key'),
    path('keys/share/', views.share_private_key, name='share_private_key'),
    path('encryption/', views.encrypt_view, name='encryption'),
    path('decryption/', views.decrypt_view, name='decryption'),
    path('download_encrypted_file/<str:file_id>/', views.download_encrypted_file, name='download_encrypted_file'),
    path('delete_encrypted_file/<str:file_id>/', views.delete_encrypted_file, name='delete_encrypted_file'),
    path('download_decrypted_file/<str:file_id>/', views.download_decrypted_file, name='download_decrypted_file'),
    path('delete_decrypted_file/<str:file_id>/', views.delete_decrypted_file, name='delete_decrypted_file'),
    path('share_encrypted_file/', views.share_encrypted_file, name='share_encrypted_file'),
    path('public/decrypt/download/<uuid:token>/', views.public_file_download_view, name='public_file_download_view'),
    path('public_file_download/<uuid:token>', views.public_file_download, name='public_file_download'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)