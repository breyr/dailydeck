from flask import Flask, flash, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
# API functions
from apicalls import company_info, company_news, stock_quote
# datetime for greetings
from datetime import datetime


# initialization
load_dotenv()
DB_PWD = os.getenv('DB_PWD')
DB_USR = os.getenv('DB_USR')
DB_ENDPOINT = os.getenv('DB_ENDPOINT')
DB_NAME = os.getenv('DB_NAME')
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{DB_USR}:{DB_PWD}@{DB_ENDPOINT}/{DB_NAME}'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# table for database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class Item(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='CASCADE'),
        nullable=False,
        # no need to add index=True, all FKs have indexes
    )
    user = relationship('User', backref='list_items')
    value = db.Column(db.String(255), nullable=False)
    

# flask forms
class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), 
                                       Length(min=4, max=20)], 
                           render_kw={'placeholder': 'Username'})
    password = PasswordField(validators=[InputRequired(), 
                                       Length(min=4, max=20)], 
                           render_kw={'placeholder': 'Password'})
    submit = SubmitField('sign up')
    
    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()
        if existing_user_name:
            raise ValidationError('That username already exists, please select another one.')
        

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), 
                                       Length(min=4, max=20)], 
                           render_kw={'placeholder': 'Username'})
    password = PasswordField(validators=[InputRequired(), 
                                       Length(min=4, max=20)], 
                           render_kw={'placeholder': 'Password'})
    submit = SubmitField('log in')
    
    
class AddToListForm(FlaskForm):
    item = StringField(validators=[InputRequired(), Length(max=255)], render_kw={'placeholder': 'Enter a stock ticker, i.e. AAPL'})
    submit = SubmitField('add')
    
    def validate_item(self, item):
        existing_item = Item.query.filter_by(username=item.data).first()
        if existing_item:
            raise ValidationError(f'{item.data.upper()} already in watchlist.')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = AddToListForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user_id = User.query.filter_by(username=current_user.username).first().id
            new_item = Item(user_id=user_id, value=form.item.data.upper())
            return redirect(url_for('dashboard'))
    else:
        curr_hr = datetime.now().hour
        if curr_hr < 12:
            greeting = 'Good morning,'
        elif curr_hr <= 18:
            greeting = 'Good afternon,'
        else:
            greeting = 'Good evening,'
            
        # pass list items to template
        items = User.query.filter_by(username=current_user.username).first().list_items
        # placeholder for stock information
        stock_info_dict = {}
        company_news_dict = {}
        if items:
            # makes api call everytime we refresh the page, so deleting an item from your list refreshes the page
            stock_tickers = [(item.id, item.value) for item in items]
            # needs to be dictionary to prevent from having duplicate items
            for tup in stock_tickers:
                if tup[0] not in stock_info_dict: # if the item id is not in the dictionary
                    stock_info_dict[tup[0]] = 'temp'
                company_information = company_info(tup[1]) # call the api for basic company info
                stock_information = stock_quote(tup[1]) # call the api for the most recent stock info
                company_news_lst = company_news(tup[1])
                if company_information:
                    stock_info_dict[tup[0]] = company_information
                if stock_information:
                    stock_info_dict[tup[0]].update(stock_information) #.update() appends to a dictionary
                if company_news_lst:
                    if tup[1] not in company_news_dict:
                        company_news_dict[tup[1]] = []
                    company_news_dict[tup[1]] = company_news_lst[:5]
        
    return render_template('dashboard.html', form=form, stock_info=stock_info_dict, news_articles=company_news_dict, greeting=greeting)

@app.route('/dashboard/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item_to_delete = Item.query.filter_by(id=item_id).first()
    db.session.delete(item_to_delete)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)