class CreateUsers < ActiveRecord::Migration[8.1]
  def change
    create_table :users do |t|
      t.string :provider, null: false
      t.string :uid, null: false
      t.string :email, null: false
      t.string :name

      t.timestamps
    end

    add_index :users, [ :provider, :uid ], unique: true
    add_index :users, :email
  end
end
