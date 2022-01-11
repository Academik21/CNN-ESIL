# Подключаем компонент для работы с формой
from django import forms
# Подключаем компонент UserCreationForm
from django.contrib.auth.forms import UserCreationForm
# Подключаем модель User
from django.contrib.auth.models import User
 
 
# Создаём класс формы
class RegistrForm(UserCreationForm):
  # Добавляем новое поле Email
  # email = forms.EmailField(max_length=254, help_text='This field is required')
  
  # Создаём класс Meta
  class Meta:
    # Свойство модели User
    model = User
    # Свойство назначения полей
    fields = ('username', 'password1', 'password2', )