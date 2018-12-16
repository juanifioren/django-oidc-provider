import copy

from django import forms
from django.core import exceptions
from django.db import models

__all__ = ["JSONMultiSelectModelField"]


class MultipleChoiceFormField(forms.MultipleChoiceField):
    def __init__(self, *args, **kwargs):
        # Django admin calls this field with the coerce parameter, but MultipleChoiceField
        # does not handle it. We don't need it anyway.
        kwargs.pop("coerce", None)
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


class JSONMultiSelectModelField(models.JSONField):
    """
    A field that is used to select multiple choices from a static set of choices.
    In python code it is represented as a set containing string identifiers for
    the selected values.
    At database level it is saved as a list of string identifiers using djangos
    JSONField.
    On forms it appears as multiple checkboxes.
    """

    def __init__(self, *args, **kwargs):
        kwargs["default"] = set
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        value = super().from_db_value(value, expression, connection)
        return self.to_python(value)

    def to_python(self, value):
        value = super().to_python(value)
        if isinstance(value, set) or value is None:
            return value
        elif isinstance(value, list):
            return set(value)
        return value

    def value_from_object(self, obj):
        """
        Returns the value of this field as currently set on the model instance.
        """
        value = super().value_from_object(obj)
        return self.to_python(value)

    def get_prep_value(self, value):
        # Used when saving to db
        db_value = super().get_prep_value(list(value))
        if db_value is None:
            return db_value
        return db_value

    def value_to_string(self, obj):
        # Used when serialising (dumpdata)
        value = self.value_from_object(obj)
        return self.get_prep_value(value)

    def formfield(self, **kwargs):
        defaults = {
            "choices_form_class": MultipleChoiceFormField,
            "widget": forms.CheckboxSelectMultiple,
        }
        defaults.update(kwargs)
        return super().formfield(**defaults)

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
                        self.error_messages["invalid_choice"],
                        code="invalid_choice",
                        params={"value": item},
                    )

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        # We don't need anything about our custom field in the context of the migration.
        # It keep things much simpler, if the migrations think this is just a boring
        # plain old JSONField.
        # See `def clone()` for more information.
        path = "django.db.models.JSONField"
        return name, path, args, kwargs

    def clone(self):
        name, path, args, kwargs = self.deconstruct()
        # Usually the Field base class would do `self.__class__(*args, **kwargs)` here.
        # However we want to pretend to migrations that we're just a normal JSONField,
        # so that is what we return here.
        # We also remove a bunch of kwargs that are not relevant in the migrations.
        kwargs = copy.deepcopy(kwargs)
        kwargs.pop("verbose_name", None)
        kwargs.pop("help_text", None)
        kwargs.pop("choices", None)
        kwargs["default"] = list
        return models.JSONField(*args, **kwargs)
