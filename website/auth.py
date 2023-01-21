from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User, Doctor, PatientComments, AppointmentBooking
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy import text


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
                return redirect(url_for('views.patient_home', user=current_user)) 
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
                return redirect(url_for("views.doc_home", doc=email, user=current_user)) 
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
            return redirect(url_for('auth.login'))
            
            
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
            return redirect(url_for('auth.doc_login'))
            
            
    return render_template("doc_sign_up.html")



@auth.route('/physician_dpmt', methods=['GET','POST'])
def physician_dpmt():

    if request.method == 'POST':
        email = request.form.get('phyemail')
        comment = request.form.get('phycomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='Physician')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("physician_dpmt.html", user=current_user)
            
            
    return render_template("physician_dpmt.html", user=current_user)

@auth.route('/pediatrician_dpmt', methods=['GET','POST'])
def pediatrician_dpmt():

    if request.method == 'POST':
        email = request.form.get('pedemail')
        comment = request.form.get('pedcomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='Pediatrician')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("pediatrician_dpmt.html", user=current_user)
            
            
    return render_template("pediatrician_dpmt.html", user=current_user)


@auth.route('/ent_dpmt', methods=['GET','POST'])
def ent_dpmt():

    if request.method == 'POST':
        email = request.form.get('entemail')
        comment = request.form.get('entcomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='ENT')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("ent_dpmt.html", user=current_user)
            
            
    return render_template("ent_dpmt.html", user=current_user)

@auth.route('/doc_home', methods=['GET','POST']) 
def doc_home():

    if request.method == 'POST':
        x = request.form.get('doc_name')
        if x == 'RAJI':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.RAJI').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'JITIN':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.JITIN').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()  
            return render_template("doc_home.html", user=current_user)  
        elif x == 'PHILIPS':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.PHILIPS').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'SIMON':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.SIMON').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'ANUSH':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.ANUSH').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'SREELATA':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.SREELATA').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'LATHA':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.LATHA').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'LEKA':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.LEKA').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'GIRIJA':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.GIRIJAZ').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'JAKOB':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.JAKOB').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'SEEMA':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.SEEMA').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'KASIM':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.KASIM').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'VYGA':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.VYGA').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'VINOD':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.VINOD').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'GAYATHRI':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.GAYATHRI').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        elif x == 'KALA':
            newx = AppointmentBooking.query.filter_by(doctor='Dr.KALA').all()
            for new in newx:
                new.status = 'False'
            db.session.commit()
            return render_template("doc_home.html", user=current_user)
        return render_template("doc_home.html", user=current_user)
            
            
    


@auth.route('/dentist_dpmt', methods=['GET','POST'])
def dentist_dpmt():

    if request.method == 'POST':
        email = request.form.get('dentemail')
        comment = request.form.get('dentcomment')
        
        
        new_com = PatientComments(email=email, comments=comment, domain='Dentist')
        db.session.add(new_com)
        db.session.commit()
            
            
        return render_template("dentist_dpmt.html", user=current_user)
            
            
    return render_template("dentist_dpmt.html", user=current_user)


@auth.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('auth.login'))

@auth.route('/patient_home', methods=['GET','POST'])
def patient_home():

    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain == 'ENT':
            return redirect(url_for('views.ent_appointment', user=current_user))
        elif domain == 'Dentist':
            return redirect(url_for('views.dentist_appointment', user=current_user))
        elif domain == 'General Physician':
            return redirect(url_for('views.physician_appointment', user=current_user))
        elif domain == 'Pediatrician':
            return redirect(url_for('views.pediatrician_appointment', user=current_user))
    appointment = request.form.get('appointments')
    if appointment:
        return redirect(url_for('views.appointment_status', user=current_user))

            
            
    return render_template("patient_home.html", user=current_user)

@auth.route('/dentist_appointment', methods=['GET','POST'])
def dentist_appointment():

    if request.method == 'POST':
        name = request.form.get('button')
        email=session['email']
        user = AppointmentBooking.query.filter_by(email=email).first()
        if not user:           
            if name=='jacob':
                doctor='Dr.JACOB'
                domain='Dentist'
                day='Monday'
                slot='9-4'
            elif name=='seema':
                doctor='Dr.SEEMA'
                domain='Dentist'
                day='Monday'
                slot='2-6'
            elif name=='kasim':
                doctor='Dr.KASIM'
                domain='Dentist'
                day='Friday'
                slot='2-7'
            elif name=='vyga':
                doctor='Dr.VYGA'
                domain='Dentist'
                day='Sunday'
                slot='10-1'
            new_app = AppointmentBooking(email=email,doctor=doctor,domain=domain,day=day,slot=slot)
            db.session.add(new_app)
            db.session.commit()
        if user:
            htmlTrippleQuoted = """
                <html>
                <head></head>
                <body>
                <script>alert("Your Booking is under Process")</script>
                </body>
                </html>
                """
            return render_template("dentist_appointment.html", user=current_user)

@auth.route('/ent_appointment', methods=['GET','POST'])
def ent_appointment():

    if request.method == 'POST':
        name = request.form.get('button')
        email=session['email']
        user = AppointmentBooking.query.filter_by(email=email).first()
        if not user:
            if name=='vinod':
                doctor='Dr.VINOD'
                domain='ENT'
                day='Sunday'
                slot='3-7'
            elif name=='gayathri':
                doctor='Dr.GAYATHRI'
                domain='ENT'
                day='Monday'
                slot='10-2'
            elif name=='kala':
                doctor='Dr.KALA'
                domain='ENT'
                day='Thursday'
                slot='2-7'
            elif name=='girija':
                doctor='Dr.GIRIJA'
                domain='ENT'
                day='Saturday'
                slot='9-11'
            new_app = AppointmentBooking(email=email,doctor=doctor,domain=domain,day=day,slot=slot)
            db.session.add(new_app)
            db.session.commit()
        
            return render_template("ent_appointment.html", user=current_user)

@auth.route('/pediatrician_appointment', methods=['GET','POST'])
def pediatrician_appointment():

    if request.method == 'POST':
        name = request.form.get('button')
        email=session['email']
        user = AppointmentBooking.query.filter_by(email=email).first()
        if user:
            if name=='anush':
                doctor='Dr.ANUSH'
                domain='Pediatrician'
                day='Sunday'
                slot='4-7'
            elif name=='sreelata':
                doctor='Dr.GSREELATA'
                domain='Pediatrician    '
                day='Wednesday'
                slot='9-11'
            elif name=='latha':
                doctor='Dr.LATHA'
                domain='Pediatrician'
                day='Thursday'
                slot='2-7'
            elif name=='leka':
                doctor='Dr.LEKA'
                domain='Pediatrician'
                day='Friday'
                slot='9-11'
            new_app = AppointmentBooking(email=email,doctor=doctor,domain=domain,day=day,slot=slot)
            db.session.add(new_app)
            db.session.commit()
        if user:
            return render_template("ent_appointment.html", user=current_user)

@auth.route('/physician_appointment', methods=['GET','POST'])
def physician_appointment():

    if request.method == 'POST':
        name = request.form.get('button')
        email=session['email']
        user = AppointmentBooking.query.filter_by(email=email).first()
        if user:
            if name=='raji':
                doctor='Dr.RAJI'
                domain='Physician'
                day='Tuesday'
                slot='8-12'
            elif name=='jitin':
                doctor='Dr.JITIN'
                domain='Physician'
                day='Wednesday'
                slot='11-4'
            elif name=='philips':
                doctor='Dr.PHILIPS'
                domain='Physician'
                day='Friday'
                slot='2-7'
            elif name=='simon':
                doctor='Dr.SIMON'
                domain='Physician'
                day='Saturday'
                slot='9-11'
            new_app = AppointmentBooking(email=email,doctor=doctor,domain=domain,day=day,slot=slot)
            db.session.add(new_app)
            db.session.commit()
        if user:
            return render_template("ent_appointment.html", user=current_user)