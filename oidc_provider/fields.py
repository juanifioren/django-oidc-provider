import json
from django.core import exceptions
from django.db import models
from django import forms


__all__ = ['JsonMultiSelectModelField']


class MultipleChoiceFormField(forms.MultipleChoiceField):
    def __init__(self, *args, **kwargs):
        # Django admin calls this field with the coerce parameter, but MultipleChoiceField
        # does not handle it. We don't need it anyway.
        kwargs.pop('coerce', None)
        super(MultipleChoiceFormField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        # MultipleChoiceField can't handle value being a set. Give it a tuple.
        if isinstance(value, set):
            value = tuple(value)
        return super(MultipleChoiceFormField, self).to_python(value)

    def prepare_value(self, value):
        # MultipleChoiceField can't handle value being a set. Give it a tuple.
        if value is None:
            return value
        return tuple(value)


class JsonMultiSelectModelField(models.Field):
    """
    A field that is used to select multiple choices from a static set of choices.
    In python code it is represented as a set containing strings the selected values.
    At database level it is saved as a json string (of a list) in a text field.
    On forms it appears as multiple checkboxes.
    """
    def __init__(self, *args, **kwargs):
        kwargs['default'] = set
        super(JsonMultiSelectModelField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return "TextField"

    def from_db_value(self, value, expression, connection, context):
        if value is None:
            return value
        return self.to_python(value)

    def to_python(self, value):
        if isinstance(value, set) or value is None:
            return value
        elif isinstance(value, list):
            return set(value)
        value = set(json.loads(value))
        return value

    def value_from_object(self, obj):
        """
        Returns the value of this field as currently set on the model instance.
        """
        value = super(JsonMultiSelectModelField, self).value_from_object(obj)
        return self.to_python(value)

    def get_prep_value(self, value):
        # Used when saving to db
        value = super(JsonMultiSelectModelField, self).get_prep_value(value)
        if value is None:
            return value
        db_value = json.dumps(list(value))
        return db_value

    def value_to_string(self, obj):
        # Used when serialising (dumpdata)
        value = self.value_from_object(obj)
        return self.get_prep_value(value)

    def formfield(self, **kwargs):
        defaults = {
            'choices_form_class': MultipleChoiceFormField,
            'widget': forms.CheckboxSelectMultiple,
        }
        defaults.update(kwargs)
        return super(JsonMultiSelectModelField, self).formfield(**defaults)

    def validate(self, value, model_instance):
        """
        Validates that all the selected choices are valid choices.
        """
        if not self.editable:
            # Skip validation for non-editable fields.
            return

        if self.choices and value not in self.empty_values:
            allowed_choices = [key for key, description in self.choices]
            for item in value:
                if item not in allowed_choices:
                    raise exceptions.ValidationError(
                        self.error_messages['invalid_choice'],
                        code='invalid_choice',
                        params={'value': item},
                    )
