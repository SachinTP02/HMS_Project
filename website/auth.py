from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User, Doctor, PatientComments
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                
                session['email'] = email
                return redirect(url_for('views.patient_home')) 
                login_user(user, remember=True)
            else:
                flash('Incorrect password, try again.', category = 'error')
        else:
            flash('Email does not exist.', category = 'error')
    return render_template("login.html", boolean=True)

@auth.route('/doc_login', methods=['GET','POST'])
def doc_login():
    if request.method == 'POST':
        email = request.form.get('doc_email')
        password = request.form.get('doc_password')
        
        user = Doctor.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category = 'success')
                session['email'] = email
                return redirect(url_for('views.patient_home')) 
                login_user(user, remember=True)
            else:
                flash('Incorrect password, try again.', category = 'error')
        else:
            flash('Email does not exist.', category = 'error')
    return render_template("doc_login.html", boolean=True)

@auth.route('/sign-up', methods=['GET','POST'])
def sign_up():

    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        phno = request.form.get('phno')
        age = request.form.get('age')
        sex = request.form.get('sex')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category = 'error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:   
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        elif len(phno) != 10:
            flash('Phone number is invalid', category='error')
        else:
            new_user = User(email=email,first_name=first_name,password=generate_password_hash(password1, method='sha256'),age=age,sex=sex,phno=phno)
            db.session.add(new_user)
            db.session.commit()
            
            
            flash('account created ', category='success')
            return render_template("login.html")
            
            
    return render_template("sign_up.html")


@auth.route('/doc_sign_up', methods=['GET','POST'])
def doc_sign_up():

    if request.method == 'POST':
        email = request.form.get('doc_email')
        first_name = request.form.get('doc_firstName')
        password1 = request.form.get('doc_password1')
        password2 = request.form.get('doc_password2')
        phno = request.form.get('doc_phno')
        domain = request.form.get('domain')
        doc_id = request.form.get('doc_id')
        
        user = Doctor.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category = 'error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:   
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        elif len(phno) != 10:
            flash('Phone number is invalid', category='error')
        else:
            new_doc = Doctor(email=email,first_name=first_name,password=generate_password_hash(password1, method='sha256'),doc_id=doc_id,domain=domain,phno=phno)
            db.session.add(new_doc)
            db.session.commit()
            
            
            flash('account created ', category='success')
            return render_template("doc_login.html")
            
            
    return render_template("doc_sign_up.html")



@auth.route('/physician_dpmt', methods=['GET','POST'])
def physician_dpmt():

    if request.method == 'POST':
        email = request.form.get('phyemail')
        comment = request.form.get('phycomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='Physician')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("physician_dpmt.html")
            
            
    return render_template("physician_dpmt.html")

@auth.route('/pediatrician_dpmt', methods=['GET','POST'])
def pediatrician_dpmt():

    if request.method == 'POST':
        email = request.form.get('pedemail')
        comment = request.form.get('pedcomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='Pediatrician')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("pediatrician_dpmt.html")
            
            
    return render_template("pediatrician_dpmt.html")


@auth.route('/ent_dpmt', methods=['GET','POST'])
def ent_dpmt():

    if request.method == 'POST':
        email = request.form.get('entemail')
        comment = request.form.get('entcomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='ENT')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("ent_dpmt.html")
            
            
    return render_template("ent_dpmt.html")

@auth.route('/dentist_dpmt', methods=['GET','POST'])
def dentist_dpmt():

    if request.method == 'POST':
        email = request.form.get('dentemail')
        comment = request.form.get('dentcomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='Dentist')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("dentist_dpmt.html")
            
            
    return render_template("dentist_dpmt.html")


@auth.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('auth.login'))