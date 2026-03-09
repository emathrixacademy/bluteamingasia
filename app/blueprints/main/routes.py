from flask import render_template, flash, redirect, url_for
from app.blueprints.main import main_bp
from app.blueprints.main.forms import ContactForm


@main_bp.route('/')
def landing():
    return render_template('landing.html')


@main_bp.route('/pricing')
def pricing():
    return render_template('pricing.html')


@main_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        flash('Thank you! We will get back to you shortly.', 'success')
        return redirect(url_for('main.contact'))
    return render_template('contact.html', form=form)
