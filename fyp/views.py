from django.shortcuts import render,redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import auth, messages
from django.contrib.auth.hashers import check_password
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now
from .models import *
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 
from .encrpytion import validate_password
from datetime import timedelta
from django.utils import timezone
import pyotp, qrcode, io, base64, json, os

def LoginView(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        hashed_password = request.POST.get('hashed_password')
        mfa_code = request.POST.get('mfa_code')
        print(f"1 username is {username}, hashed_password is {hashed_password}, mfa_code is {mfa_code}")

        try:
            user_queryset = User.objects.filter(name=username)
            if user_queryset.exists():
                user = user_queryset.first()
                print(f"User found: {user}")

                if validate_password(hashed_password, username, user.passwords):
                    totp = pyotp.TOTP(user.mfakey)
                    if totp.verify(mfa_code):
                        request.session['userid'] = user.userid
                        request.session['username'] = user.name
                        request.session.set_expiry(21600)
                        print(f"User {username} successfully logged in.")
                        return redirect('index')
                    else:
                        messages.error(request, "Invalid MFA code.")
                        print("Invalid MFA code.")
                        return render(request, 'login.html')
                else:
                    messages.error(request, "Invalid password.")
                    print("Invalid password.")
                    return render(request, 'login.html')
            else:
                messages.error(request, "Invalid username")
                print("Invalid username")
                return render(request, 'login.html')
        except Exception as e:
            messages.error(request, "Invalid username or password.")
            print(f"{e}")
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')

def IndexView(request):
    userid = request.session.get('userid')
    if not userid:
        request.session.flush()
        messages.error(request, "User not logged in")
        return redirect('login')

    passwords_with_expiry = []

    try:
        user_queryset = User.objects.filter(userid=userid)
        if user_queryset.exists():
            password_queryset = Password.objects.filter(created_by=userid)
            if password_queryset.exists():
                for password in password_queryset:
                    expiration_days = int(password.expiration_day)
                    expiry_date = password.updated_at + timedelta(days=expiration_days)
                    time_remaining = expiry_date - timezone.now()
                    days_remaining = time_remaining.days
                    hours_remaining, remainder = divmod(time_remaining.seconds, 3600)
                    minutes_remaining, _ = divmod(remainder, 60)

                    passwords_with_expiry.append({
                        'password_id': password.passwordid,
                        'name': password.name,
                        'password': '*******',  
                        'real_password': password.password,  
                        'created_by': password.created_by.name,
                        'expiration_day': password.expiration_day,
                        'days_remaining': days_remaining,
                        'hours_remaining': hours_remaining,
                        'minutes_remaining': minutes_remaining
                    })
            else:
                passwords_with_expiry = []
                messages.info(request, "No passwords saved")
        else:
            request.session.flush()
            messages.error(request, "User ID does not exist")
            return redirect('login')
    except Exception as e:
        request.session.flush()
        messages.error(request, "An error occurred")
        print(f"{e}")
        return redirect('login')

    return render(request, 'index.html', {'passwords': passwords_with_expiry})

@csrf_exempt
def verify_mfa(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            entered_code = data.get('mfa_code')
            password_id = data.get('password_id')
            user = User.objects.get(name=request.session.get('username'))
            print(entered_code)
            totp = pyotp.TOTP(user.mfakey)
            if totp.verify(entered_code):
                password = Password.objects.get(pk=password_id)
                updated_at_str = user.updated_at.strftime('%Y%m%d%H%M%S%f')
                combined_key = (user.mfakey + updated_at_str).encode('utf-8')
                key = base64.b32encode(combined_key)

                if len(key) < 32:
                    key = key.ljust(32, b'\0')
                else:
                    key = key[:32]

                encrypted_password = password.password  # Only return encrypted password, no nonce!

                return JsonResponse({
                    'status': 'success',
                    'encrypted_password': encrypted_password,  # Send encrypted data
                    'key': key.hex()  # Send the encryption key as hex
                })
            else:
                return JsonResponse({'status': 'failure'})

        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error'})
# def verify_mfa(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body.decode('utf-8'))
#             entered_code = data.get('mfa_code')
#             password_id = data.get('password_id')
#             user = User.objects.get(name=request.session.get('username'))

#             totp = pyotp.TOTP(user.mfakey)
#             if totp.verify(entered_code):
#                 password = Password.objects.get(pk=password_id)
#                 updated_at_str = user.updated_at.strftime('%Y%m%d%H%M%S%f')
#                 combined_key = (user.mfakey + updated_at_str).encode('utf-8')
#                 key = base64.b32encode(combined_key)
#                 if len(key) < 32:
#                     key = key.ljust(32, b'\0')
#                 else:
#                     key = key[:32]
#                 encrypted_password, nonce = password.password.split(':')
#                 encrypted_password = bytes.fromhex(encrypted_password)
#                 nonce = bytes.fromhex(nonce)
#                 chacha = ChaCha20Poly1305(key)
#                 decrypted_password = chacha.decrypt(nonce, encrypted_password, None).decode('utf-8')

#                 return JsonResponse({'status': 'success', 'password': decrypted_password})
#             else:
#                 return JsonResponse({'status': 'failure'})
#         except Exception as e:
#             print(f"Error: {e}")
#             return JsonResponse({'status': 'error', 'message': str(e)})
#     return JsonResponse({'status': 'error'})

def RegisterView(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        email = request.POST.get('email')
        print(f"username is {username}, password is {password1} = {password2}, email = {email}")

        if password1 == password2:
            if User.objects.filter(name=username).exists():
                messages.info(request, f"Username {username} has already been taken")
                return redirect('register')
            elif User.objects.filter(email=email).exists():
                messages.info(request, f"Email {email} has already been taken")
                return redirect('register')
            else:
                try:
                    new_user = User(name=username, passwords=password1, email=email)
                    new_user.mfakey = pyotp.random_base32()
                    new_user.save()

                    otp_uri = pyotp.totp.TOTP(new_user.mfakey).provisioning_uri(
                        username, issuer_name="Password Manager"
                    )
                    qr = qrcode.make(otp_uri)
                    buffer = io.BytesIO()
                    qr.save(buffer, format="PNG")
                    qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")
                    qr_code_data_uri = f"data:image/png;base64,{qr_code}"

                    request.session['userid'] = new_user.userid
                    request.session['username'] = new_user.name
                    request.session['qr_code_data_uri'] = qr_code_data_uri

                    print(f"User {username} created successfully")
                    return redirect('mfa')
                except Exception as e:
                    print(f"Error creating user: {e}")
                    messages.error(request, f"Error creating user: {e}")
                    return render(request, 'register.html')
        else:
            messages.error(request, "Passwords do not match")
            return render(request, 'register.html')
    return render(request, 'register.html')

def SuccessView(request):
    return render(request, 'success.html', locals())

def LogoutView(request):
    request.session.flush()
    messages.info(request, "Logout successful!")
    return render(request, 'login.html')

def MFAView(request):
    username = request.session.get('username')
    qr_code_data_uri = request.session.get('qr_code_data_uri')
    if not username or not qr_code_data_uri:
        return redirect('register')

    if request.method == 'POST':
        otp_token = request.POST.get('otp_token')

        try:
            user = User.objects.get(name=username)
            totp = pyotp.TOTP(user.mfakey)

            if totp.verify(otp_token):
                request.session['userid'] = user.userid
                request.session['username'] = user.name
                request.session.set_expiry(21600)
                messages.success(request, "MFA setup successful!")
                return redirect('index')
            else:
                messages.error(request, "Invalid OTP. Please try again.")
        except User.DoesNotExist:
            messages.error(request, "User does not exist.")
            return redirect('register')
    print(username)
    return render(request, 'mfa.html', {'qr_code_data_uri': qr_code_data_uri, 'username': username})

@csrf_exempt
def CreateView(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            password_name = data.get('name')
            expiration_day = data.get('expiration_day')

            user = User.objects.get(name=request.session.get('username'))
            updated_at_str = user.updated_at.strftime('%Y%m%d%H%M%S%f')
            combined_key = (user.mfakey + updated_at_str).encode('utf-8')
            key = base64.b32encode(combined_key)

            if len(key) < 32:
                key = key.ljust(32, b'\0')
            else:
                key = key[:32]

            # Store password entry WITHOUT encryption
            password_record = Password.objects.create(
                name=password_name,
                password="NoPassword",
                expiration_day=expiration_day,
                nonce=None,  # ✅ No nonce yet!
                created_by=user
            )

            # Return key for client-side encryption
            return JsonResponse({
                'status': 'success',
                'passwordid': password_record.passwordid,  # ✅ Send password ID
                'key': key.hex()  # ✅ Send key for client-side encryption
            })

        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error'})
# def CreateView(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body.decode('utf-8'))
#             password_name = data.get('name')
#             password_value = data.get('password')
#             expiration_day = data.get('expiration_day')
#             print(expiration_day)
#             user = User.objects.get(name=request.session.get('username'))
#             created_at_str = user.updated_at.strftime('%Y%m%d%H%M%S%f')
#             combined_key = (user.mfakey + created_at_str).encode('utf-8')
#             key = base64.b32encode(combined_key)
#             if len(key) < 32:
#                 key = key.ljust(32, b'\0')
#             else:
#                 key = key[:32]
#             chacha = ChaCha20Poly1305(key)
#             nonce = os.urandom(12)
#             encrypted_password = chacha.encrypt(nonce, password_value.encode(), None)

#             Password.objects.create(
#                 name=password_name,
#                 password=encrypted_password.hex() + ":" + nonce.hex(),
#                 expiration_day=expiration_day,
#                 nonce=nonce,
#                 created_by=user
#             )
#             return JsonResponse({'status': 'success'})
#         except Exception as e:
#             print(f"Error: {e}")
#             return JsonResponse({'status': 'error', 'message': str(e)})
#     return JsonResponse({'status': 'error'})

@csrf_exempt
def store_encrypted_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            password_id = data.get('passwordid')
            encrypted_password = data.get('encrypted_password')

            # Retrieve password record and update with encrypted values
            password_record = Password.objects.get(pk=password_id)
            password_record.password = encrypted_password  # ✅ Store only encrypted password (no nonce)
            password_record.save()

            return JsonResponse({'status': 'success'})

        except Exception as e:
            print(f"Error storing encrypted password: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error'})

@csrf_exempt
def DeleteView(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            password_id = data.get('password_id')
            mfa_code = data.get('mfa_code')
            user = User.objects.get(name=request.session.get('username'))
            
            totp = pyotp.TOTP(user.mfakey)
            if not totp.verify(mfa_code):
                return JsonResponse({'status': 'error', 'message': 'Invalid MFA code'})

            Password.objects.filter(passwordid=password_id, created_by=user).delete()
            return JsonResponse({'status': 'success'})
        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error'})

@csrf_exempt
def ModifyView(request):

    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            password_id = data.get('password_id')
            password_name = data.get('name')
            expiration_day = data.get('expiration_day')
            mfa_code = data.get('mfa_code')
            user = User.objects.get(name=request.session.get('username'))

            # Generate properly formatted update time before updating
            updated_at = now()  # This is a proper datetime object
            updated_at_str = updated_at.strftime('%Y-%m-%d %H:%M:%S.%f')  # Correct format

            # Verify MFA Code
            totp = pyotp.TOTP(user.mfakey)
            if not totp.verify(mfa_code):
                return JsonResponse({'status': 'error', 'message': 'Invalid MFA code'})

            # Update password entry in SQLite (password temporarily "NeedUpdate")
            Password.objects.filter(passwordid=password_id, created_by=user).update(
                name=password_name,
                password="NeedUpdate",
                expiration_day=expiration_day,
                updated_at=updated_at  # Save as a proper datetime object
            )

            # Generate new encryption key
            combined_key = (user.mfakey + updated_at_str).encode('utf-8')
            key = base64.b32encode(combined_key)

            if len(key) < 32:
                key = key.ljust(32, b'\0')
            else:
                key = key[:32]

            # Send back new encryption key with correctly formatted `updated_at`
            return JsonResponse({'status': 'success', 'key': key.hex(), 'updated_at': updated_at_str})

        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error'})

@csrf_exempt
def verify_mfaCodeView(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            entered_code = data.get('mfa_code')
            user = User.objects.get(name=request.session.get('username'))
            print(entered_code)
            totp = pyotp.TOTP(user.mfakey)
            if totp.verify(entered_code):
                return JsonResponse({'status': 'success'})
        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error'})