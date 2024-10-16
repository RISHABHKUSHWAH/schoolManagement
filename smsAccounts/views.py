from django.shortcuts import render
from django.contrib.auth.models import User
import re
from django.contrib.auth.hashers import make_password
from django.shortcuts import render,HttpResponse,redirect,HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import authenticate,logout
def is_valid_password(password):
    # Check length
    if len(password) < 8:
        return False

    # Check for at least one letter and one digit
    if not re.search(r'[a-zA-Z]', password) or not re.search(r'\d', password):
        return False

    # Check for similarity to personal information
    if re.search(r'(?i)password|123456|qwerty', password):
        return False

    # Check if password is entirely numeric
    if password.isdigit():
        return False
    return True

def signup(request):
    msg=None
    if request.method == "POST":
        email = request.POST['email']
        username = email
        password= request.POST['password']
        confirmPassword = request.POST['confirmPassword']
        isUser = True
        try:
        # Attempt to retrieve the user based on the provided username (name)
            username = User.objects.get(username=email)
             # If the user exists, you can perform further actions here
        except User.DoesNotExist:
            isUser = False
            if password == confirmPassword:
                if is_valid_password(password):
                    password = make_password(password)
                    saveData = User(username = email, email = email, password = password)
                    saveData.save()
                else:
                    msg = 'Password must contain at least 8 characters, including one letter and one digit, and cannot be too similar to personal information.'    
            else:
                msg="password and conf password are differnt"
        if(isUser):
            msg="  Username already exists"          
    if msg != None:
        # alert_message = msg
        return render(request,'singupLogin.html',{'dataSignUp':msg})
        # js_script = f"<script>alert('{alert_message}');</script>"
        # response = HttpResponse(render(request, 'singupLogin.html'))
        # response.content += js_script.encode('utf-8')
        # return response
    else:
        return render(request,'singupLogin.html')

def logIn(request):
    if request.method == "POST":
        username = request.POST['email']
        password = request.POST['password']
        try:
            user = User.objects.get(username=username)
        except:
            messages.error(request, 'Username does not exist!')
        user = authenticate(username = username ,password = password)
        if user is not None:
            auth_login(request,user)
            print("user is authenticate") 
        else:
            msg = 'Username or password is incorrect!'
            return render(request,'singupLogin.html',{'data':msg})
        # auth_login(request,user)
        return redirect('dashboard')
    else:
        print("not login")
        return redirect('/')  
         
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/signup/')