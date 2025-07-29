from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from bson.objectid import ObjectId
from datetime import datetime
from app import mongo

post_bp = Blueprint('posts',__name__)

# @post_bp('/posts/new', methods=['GET'])
# @login_required
# def new_post():
#     return render_template('create_post.html')

# @post_bp('/posts/new', methods=['POST'])
# @login_required
# def create_post():
